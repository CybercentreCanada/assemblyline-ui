import json
import os
import re
import shutil
import socket
import tempfile
from typing import List
from urllib.parse import urlparse

import requests

from assemblyline.common.dict_utils import get_recursive_delta, recursive_update
from assemblyline.common.file import make_uri_file
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.models.config import HASH_PATTERN_MAP, SubmissionProfile
from assemblyline.odm.models.user import ROLES
from assemblyline.odm.models.user_settings import DEFAULT_USER_PROFILE_SETTINGS
from assemblyline_ui.config import (
    ARCHIVESTORE,
    CLASSIFICATION,
    FILESTORE,
    IDENTIFY,
    SERVICE_LIST,
    STORAGE,
    SUBMISSION_PROFILES,
    SUBMISSION_TRAFFIC,
    config,
)

# Baseline fetch methods
FETCH_METHODS = set(list(HASH_PATTERN_MAP.keys()) + ['url'])

# Update our fetch methods based on what's in our configuration
[FETCH_METHODS.update(set(x.hash_types)) for x in config.submission.file_sources]

# Baseline URL Generators
URL_GENERATORS = {'url'}

# Update our URL Generators based on what's in our configuration
[URL_GENERATORS.update(set(x.hash_types)) for x in config.submission.file_sources if not x.download_from_url]


try:
    MYIP = socket.gethostbyname(config.ui.fqdn)
except socket.gaierror:
    MYIP = '127.0.0.1'



#############################
# download functions
class FileTooBigException(Exception):
    pass


class InvalidUrlException(Exception):
    pass


class ForbiddenLocation(Exception):
    pass

def apply_changes_to_profile(profile: SubmissionProfile, updates: dict, user: dict) -> dict:
    validated_profile = profile.params.as_primitives(strip_null=True)

    updates.setdefault("services", {})
    updates["services"].setdefault("selected", [])
    updates["services"].setdefault("excluded", [])

    # Append the exclusion list set by the profile
    updates['services']['excluded'] = updates['services']['excluded'] + \
        list(validated_profile.get("services", {}).get("excluded", []))

    if ROLES.submission_customize not in user['roles'] and "administration" not in user['roles']:
        # Check the services parameters
        for param_type, list_of_params in profile.restricted_params.items():

            # Check if there are restricted submission parameters
            if param_type == "submission":
                requested_params = (set(list_of_params) & set(updates.keys())) - set({'services', 'service_spec'})
                if requested_params:
                    params = ', '.join(f"\"{p}\"" for p in requested_params)
                    raise PermissionError(f"User isn't allowed to modify the {params} parameters of {profile.display_name} profile")

            # Check if there are restricted service parameters
            else:
                service_spec = updates.get('service_spec', {}).get(param_type, {})
                requested_params = set(list_of_params) & set(service_spec)
                if requested_params:
                    params = ', '.join(f"\"{p}\"" for p in requested_params)
                    raise PermissionError(f"User isn't allowed to modify the {params} parameters of \"{param_type}\" service in \"{profile.display_name}\" profile")

        for svr in SERVICE_LIST:
            selected_svrs = updates['services']['selected']
            excluded_svrs = updates['services']['excluded']

            if svr['enabled'] and \
                (svr['name'] in selected_svrs or svr['category'] in selected_svrs) and \
                (svr['name'] in excluded_svrs or svr['category'] in excluded_svrs):

                raise PermissionError(f"User isn't allowed to select the {svr['name']} service of \"{svr['category']}\" in \"{profile.display_name}\" profile")

    return recursive_update(validated_profile, updates)

def fetch_file(method: str, input: str, user: dict, s_params: dict, metadata: dict,  out_file: str,
               default_external_sources: List[str], name: str):
    sha256 = None
    fileinfo = None
    # If the method is by SHA256 hash, check to see if we already have that file
    if method == "sha256":
        fileinfo = STORAGE.file.get_if_exists(input, as_obj=False)
    elif method == "url":
        # If the method is by URL, check if we have a file with matching `uri_info.uri` as input
        res = STORAGE.file.search(f'uri_info.uri:"{input}"', rows=1, as_obj=False)
        if res['total']:
            fileinfo = res['items'][0]
    elif method in FETCH_METHODS:
        # If the method is by a field that's known in our File model, query the datastore for the SHA256
        res = STORAGE.file.search(f'{method}:"{input}"', rows=1, as_obj=False)
        if res['total']:
            fileinfo = res['items'][0]

    found = False
    if fileinfo:
        fileinfo.pop('id', None)
        sha256 = fileinfo['sha256']
        # File exists in the DB, so let's retrieve it from the filestore and write to the out file
        if CLASSIFICATION.is_accessible(user['classification'], fileinfo['classification']):
            # User has access to the file
            if FILESTORE.exists(sha256):
                # File exists in the filestore
                FILESTORE.download(sha256, out_file)
                found = True

            elif ARCHIVESTORE and ARCHIVESTORE != FILESTORE and \
                    ROLES.archive_download in user['roles'] and ARCHIVESTORE.exists(sha256):
                # File exists in the archivestore
                ARCHIVESTORE.download(sha256, out_file)
                found = True

            if found:
                # Found the file, now apply its classification
                s_params['classification'] = CLASSIFICATION.max_classification(s_params['classification'],
                                                                                fileinfo['classification'])

                if (
                    fileinfo["type"].startswith("uri/")
                    and "uri_info" in fileinfo
                    and "uri" in fileinfo["uri_info"]
                ):
                    # Set a description if one hasn't been already set
                    s_params['description']= s_params.get('description',
                                                          f"Inspection of URL: {fileinfo['uri_info']['uri']}")

    if not found:
        # File doesn't exist in our system, therefore it has to be retrieved

        # Check if external submit is allowed
        if method == "url":
            if not config.ui.allow_url_submissions:
                raise PermissionError("URL submissions are disabled in this system")

            # Create an AL-URI file to be tasked by a downloader service (ie. URLDownloader)
            with tempfile.TemporaryDirectory() as dir_path:
                shutil.move(make_uri_file(dir_path, input), out_file)

            found = True
        elif not default_external_sources:
            # No external sources specified and the file being asked for doesn't exist in the system
            raise FileNotFoundError(f"{method.upper()} does not exist in Assemblyline")
        else:
            if method == "sha256":
                # Legacy support: Merge the sources from `sha256_sources` + `file_sources` that support SHA256 fetching
                available_sources = [x for x in config.submission.sha256_sources
                                    if CLASSIFICATION.is_accessible(user['classification'], x.classification) and
                                    x.name in default_external_sources] + \
                                    [x for x in config.submission.file_sources
                                    if "sha256" in x.hash_types and
                                    CLASSIFICATION.is_accessible(user['classification'], x.classification)
                                    and x.name in default_external_sources]
            else:
                # Otherwise go based on the `file_sources` configuration
                available_sources = [x for x in config.submission.file_sources
                                    if method in x.hash_types and
                                    CLASSIFICATION.is_accessible(user['classification'], x.classification)
                                    and x.name in default_external_sources]

            for source in available_sources:
                # Building final URL and data block
                src_url = source.url.replace(source.replace_pattern, input)
                src_data = source.data.replace(source.replace_pattern, input) if source.data else None
                failure_pattern = source.failure_pattern.encode('utf-8') if source.failure_pattern else None

                # If we should download from the source
                if source.download_from_url:
                    # Get the file from the source URL
                    dl_from = download_from_url(src_url, out_file, data=src_data, method=source.method,
                                                headers=source.headers, proxies=source.proxies,
                                                verify=source.verify, validate=False,
                                                failure_pattern=failure_pattern,
                                                ignore_size=s_params.get('ignore_size', False))
                    if dl_from is not None:
                        found = True
                else:
                    # Check if we are allowed to task this system with URLs
                    if not config.ui.allow_url_submissions:
                        raise PermissionError("URL submissions are disabled in this system")

                    # Create an AL-URI file to be tasked by a downloader service (ie. URLDownloader)
                    with tempfile.TemporaryDirectory() as dir_path:
                        shutil.move(make_uri_file(dir_path, src_url), out_file)

                    found = True

                if found:
                    # Apply minimum classification for the source
                    s_params['classification'] = \
                        CLASSIFICATION.max_classification(s_params['classification'],
                                                            source.classification)

                    # Applying the source used to the metadata
                    metadata['original_source'] = source.name

                    # Forcing service selection
                    for service in source.select_services:
                        if service not in s_params['services']['selected']:
                            s_params['services']['selected'].append(service)

                    # Check if the downloaded content has the same hash as the fetch method
                    if method in HASH_PATTERN_MAP and name == input:
                        hash = IDENTIFY.fileinfo(out_file)[method]
                        if hash != input:
                            # Rename the file to the hash of the downloaded content to avoid confusion
                            name = hash

                    # A source suited for the task was found, skip the rest
                    break


    return found, fileinfo, name

def update_submission_parameters(s_params: dict, data: dict, user: dict) -> dict:
    s_profile = SUBMISSION_PROFILES.get(data.get('submission_profile'))
    submission_customize = ROLES.submission_customize in user['roles']

    # Ensure classification is set based on the user before applying updates
    classification = s_params.get("classification", user['classification'])

    # Apply provided params (if the user is allowed to)
    if submission_customize:
        s_params.update(data.get("params", {}))
    elif not s_profile:
        # No profile specified, raise an exception back to the user
        raise Exception(f"You must specify a submission profile. One of: {list(SUBMISSION_PROFILES.keys())}")

    if s_profile:
        if not CLASSIFICATION.is_accessible(user['classification'], s_profile.classification):
            # User isn't allowed to use the submission profile specified
            raise PermissionError(f"You aren't allowed to use '{s_profile.name}' submission profile")
        # Apply the profile (but allow the user to change some properties)
        s_params = recursive_update(s_params, data.get("params", {}))
        s_params = get_recursive_delta(DEFAULT_USER_PROFILE_SETTINGS, s_params)
        s_params = apply_changes_to_profile(s_profile, s_params, user)
        s_params = recursive_update(DEFAULT_USER_PROFILE_SETTINGS, s_params)

    # Ensure the description key exists in the resulting submission params
    s_params.setdefault("description", "")
    s_params.setdefault("classification", classification)
    return s_params


def refang_url(url):
    '''
    Refangs a url of text. Based on source of: https://pypi.org/project/defang/
    '''
    new_url = re.sub(r'[\(\[](\.|dot)[\)\]]', '.', url, flags=re.IGNORECASE)
    new_url = re.sub(r'^h[x]{1,2}p([s]?)\[?:\]?//', r'http\1://', new_url, flags=re.IGNORECASE)
    new_url = re.sub(r'^fxp(s?)\[?:\]?//', r'ftp\1://', new_url, flags=re.IGNORECASE)
    return new_url


def validate_url(url, refang=True):
    try:
        if refang:
            valid_url = refang_url(url)
        else:
            valid_url = url
        parsed = urlparse(valid_url)
    except Exception:
        raise InvalidUrlException('Url provided is invalid.')

    host = parsed.hostname or parsed.netloc

    if host:
        try:
            cur_ip = socket.gethostbyname(host)
        except socket.gaierror:
            cur_ip = None

        if cur_ip is None:
            raise ForbiddenLocation(f"Host '{host}' cannot be resolved.")

        if is_ip_reserved(cur_ip):
            raise ForbiddenLocation(
                f"Host '{host}' resolves to a reserved IP address: '{cur_ip}'. The URL will not be downloaded.")

    return valid_url


def validate_redirect(r, **_):
    if r.is_redirect:
        location = safe_str(r.headers['location'])
        try:
            validate_url(location, refang=False)
        except Exception:
            raise InvalidUrlException('Url provided is invalid.')


def download_from_url(download_url, target, data=None, method="GET",
                      headers={}, proxies={}, verify=True, validate=True, failure_pattern=None,
                      timeout=None, ignore_size=False):
    hooks = None
    if validate:
        url = validate_url(download_url)
        hooks = {'response': validate_redirect}
    else:
        url = download_url

    # Create a requests sessions
    session = requests.Session()
    session.verify = verify

    try:
        session_function = {
            "GET": session.get,
            "POST": session.post,
        }[method]
    except Exception:
        raise InvalidUrlException(f"Unsupported method used: {method}")

    r = session_function(url, data=data, hooks=hooks, headers=headers, proxies=proxies, stream=True,
                         timeout=timeout, allow_redirects=True)

    if r.ok:
        if int(r.headers.get('content-length', 0)) > config.submission.max_file_size and not ignore_size:
            raise FileTooBigException("File too big to be scanned "
                                      f"({r.headers['content-length']} > {config.submission.max_file_size}).")

        written = 0

        with open(target, 'wb') as f:
            for chunk in r.iter_content(chunk_size=64 * 1024):
                if chunk:  # filter out keep-alive new chunks
                    if failure_pattern and failure_pattern in chunk:
                        f.close()
                        os.unlink(target)
                        return None

                    written += len(chunk)
                    if written > config.submission.max_file_size and not ignore_size:
                        f.close()
                        os.unlink(target)
                        raise FileTooBigException("File too big to be scanned.")
                    f.write(chunk)

            if written > 0:
                return [r.url for r in r.history if r.url != url]

    return None


def get_or_create_summary(sid, results, user_classification, completed):
    user_classification = CLASSIFICATION.normalize_classification(user_classification, long_format=False)
    cache_key = f"{sid}_{user_classification}_m{config.submission.verdicts.malicious}" \
        f"_hs{config.submission.verdicts.highly_suspicious}_s{config.submission.verdicts.suspicious}" \
        f"_i{config.submission.verdicts.info}_"
    for illegal_char in [" ", ":", "/"]:
        cache_key = cache_key.replace(illegal_char, "")

    summary_cache = STORAGE.submission_summary.get_if_exists(cache_key, as_obj=False)

    if not summary_cache:
        summary = STORAGE.get_summary_from_keys(
            results, cl_engine=CLASSIFICATION, user_classification=user_classification,
            keep_heuristic_sections=True)

        expiry = now_as_iso(config.datastore.cache_dtl * 24 * 60 * 60)
        partial = not completed or "missing_results" in summary or "missing_files" in summary

        # Do not cache partial summary
        if not partial:
            summary_cache = {
                "attack_matrix": json.dumps(summary['attack_matrix']),
                "tags": json.dumps(summary['tags']),
                "expiry_ts": expiry,
                "heuristics": json.dumps(summary['heuristics']),
                "classification": summary['classification'],
                "filtered": summary["filtered"],
                "heuristic_sections": json.dumps(summary['heuristic_sections']),
                "heuristic_name_map": json.dumps(summary['heuristic_name_map'])
            }
            STORAGE.submission_summary.save(cache_key, summary_cache)

        return {
            "attack_matrix": summary['attack_matrix'],
            "tags": summary['tags'],
            "expiry_ts": expiry,
            "heuristics": summary['heuristics'],
            "classification": summary['classification'],
            "filtered": summary["filtered"],
            "partial": partial,
            "heuristic_sections": summary['heuristic_sections'],
            "heuristic_name_map": summary['heuristic_name_map']
        }

    return {
        "attack_matrix": json.loads(summary_cache['attack_matrix']),
        "tags": json.loads(summary_cache['tags']),
        "expiry_ts": summary_cache["expiry_ts"],
        "heuristics": json.loads(summary_cache['heuristics']),
        "classification": summary_cache['classification'],
        "filtered": summary_cache["filtered"],
        "partial": False,
        "heuristic_sections": json.loads(summary_cache['heuristic_sections']),
        "heuristic_name_map": json.loads(summary_cache['heuristic_name_map'])
    }


def submission_received(submission):
    SUBMISSION_TRAFFIC.publish(SubmissionMessage({
        'msg': submission,
        'msg_type': 'SubmissionReceived',
        'sender': 'ui',
    }).as_primitives())
