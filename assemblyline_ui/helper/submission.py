import base64
import hashlib
import io
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
from copy import deepcopy
from typing import Dict, List
from urllib.parse import urlparse

import requests
from flask import Request

from assemblyline.common.classification import InvalidClassification
from assemblyline.common.codec import decode_file
from assemblyline.common.dict_utils import (
    flatten,
    get_recursive_delta,
    recursive_update,
    strip_nulls,
)
from assemblyline.common.file import make_uri_file
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.common.uid import get_random_id
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline.odm.models.config import HASH_PATTERN_MAP, SubmissionProfile
from assemblyline.odm.models.user import ROLES
from assemblyline.odm.models.user_settings import DEFAULT_SUBMISSION_PROFILE_SETTINGS
from assemblyline_ui.config import (
    ARCHIVESTORE,
    CLASSIFICATION,
    FILESTORE,
    IDENTIFY,
    SERVICE_LIST,
    STORAGE,
    SUBMISSION_PROFILES,
    SUBMISSION_TRAFFIC,
    TEMP_SUBMIT_DIR,
    config,
    metadata_validator,
)
from assemblyline_ui.helper.service import ui_to_submission_params

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
    def __init__(self, file_size, *args):
        super().__init__(msg=f"File too big to be scanned ({file_size} > {config.submission.max_file_size}).", *args)
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

    return recursive_update(validated_profile, strip_nulls(updates))


# This should be a common function used by endpoints to trigger a submission that provides a baseline
def init_submission(request: Request, user: Dict, endpoint: str):
    # Default output
    out_file = None
    name = None
    fileinfo = None

    # Prepare output directory/file path
    if endpoint != "ui":
        out_dir = os.path.join(TEMP_SUBMIT_DIR, get_random_id())
        os.makedirs(out_dir, exist_ok=True)
        out_file = os.path.join(out_dir, get_random_id())

    # Get data block and binary blob
    string_type, string_value = None, None
    if 'multipart/form-data' in request.content_type:
        if 'json' in request.values:
            data = json.loads(request.values['json'])
        else:
            data = {}

        binary = request.files['bin']
        name = safe_str(os.path.basename(data.get("name", binary.filename) or ""))
    elif 'application/json' in request.content_type:
        data = request.json
        binary = data.get('plaintext', '').encode() or base64.b64decode(data.get('base64', ''))
        file_size = len(binary)
        if file_size > config.submission.max_file_size:
            raise FileTooBigException(file_size)

        # Determine if we're expected to fetch a file
        for method in FETCH_METHODS:
            if data.get(method):
                string_type, string_value = method, data[method]
                break

        if string_type in URL_GENERATORS:
            string_value = refang_url(string_value)
            name = string_value
        else:
            hash = string_value
            if binary:
                hash = safe_str(hashlib.sha256(binary).hexdigest())
                binary = io.BytesIO(binary)
            name = safe_str(os.path.basename(data.get("name", None) or hash or ""))
    else:
        raise Exception("Invalid content type")

    user_settings = STORAGE.user_settings.get(user['uname'], as_obj=False) or {}
    default_external_sources = user_settings.get("default_external_sources", [])

    # Extract submission parameters from data block
    if "ui_params" in data:
        # Submission was triggered from the frontend which stores data in a different format, normalize to what's expected
        ui_params: dict = data.pop("ui_params")
        data["params"] = ui_to_submission_params(ui_params)

        # Use the external sources provided by the request otherwise default to user settings
        default_external_sources = ui_params.pop('default_external_sources', []) or default_external_sources
    else:
        # Assume the data was submitted to the API directly in the expected format
        default_external_sources = data.get('params', {}).pop('default_external_sources', []) or default_external_sources

    # Validate submission parameters provided in data block
    s_params = update_submission_parameters(data, user, user_settings.get('submission_profiles', {}))

    # Check the validity of some parameters relative to system configurations
    if config.submission.max_dtl > 0:
        # Ensure that the TTL doesn't exceed the maximum allowed
        if s_params['ttl'] != 0:
            s_params['ttl'] = min(s_params['ttl'], config.submission.max_dtl)
        else:
            s_params['ttl'] = config.submission.max_dtl

    # Get the metadata
    metadata = flatten(data.get('metadata', {}))

    if endpoint == "ui":
        # If this was submitted through the UI, then the file is in the cachestore
        # Return the validated submission parameters and metadata
        return data, out_file, name, fileinfo, s_params, metadata
    elif not binary:
        # If the file wasn't provided in a binary blob, then seek to fetch the file from an external source
        if string_type:
            found, fileinfo, name = fetch_file(string_type, string_value, user, s_params, metadata, out_file,
                                    default_external_sources, name)
            if not found:
                raise FileNotFoundError(
                    f"{string_type.upper()} does not exist in Assemblyline or any of the selected sources")
        else:
            raise Exception("Missing file to scan. No binary or fetching method provided.")
    else:
        with open(out_file, "wb") as my_file:
            shutil.copyfileobj(binary, my_file, 16384)

    if not fileinfo:
        fileinfo = IDENTIFY.fileinfo(out_file, skip_fuzzy_hashes=True, calculate_entropy=False)
        if STORAGE.file.exists(fileinfo['sha256']):
            # Re-use existing file information
            fileinfo = STORAGE.file.get(fileinfo['sha256'], as_obj=False)
        elif endpoint == 'ingest':
            # If this is the ingest endpoint, then calculate the full file information
            fileinfo = IDENTIFY.fileinfo(out_file)
        else:
            # Otherwise if this is the submit endpoint, full calculation isn't necessary
            fileinfo = IDENTIFY.fileinfo(out_file, skip_fuzzy_hashes=True, calculate_entropy=False)

    if fileinfo['size'] > config.submission.max_file_size and not s_params.get('ignore_size', False):
        raise FileTooBigException(file_size=fileinfo['size'])
    elif fileinfo['size'] == 0:
        raise Exception("File empty.")

    # Validate metadata depending on endpoint
    if endpoint in ["submit", "ui"]:
        # Get metadata validation configuration
        strict = 'submit' in config.submission.metadata.strict_schemes
        scheme = config.submission.metadata.submit
    else:
        # Get metadata validation configuration
        strict = s_params.get('type') in config.submission.metadata.strict_schemes
        scheme = config.submission.metadata.ingest.get('_default', {})
        scheme.update(config.submission.metadata.ingest.get(s_params.get('type'), {}))

    # If an error is returned as part of validation, raise it back to user
    metadata_error = metadata_validator.check_metadata(metadata, validation_scheme=scheme, strict=strict)
    if metadata_error:
        raise Exception(metadata_error[1])

    # If the submission was set to auto-archive we need to validate the archive metadata fields also
    if s_params.get('auto_archive', False):
        strict = 'archive' in config.submission.metadata.strict_schemes
        metadata_error = metadata_validator.check_metadata(
            metadata, validation_scheme=config.submission.metadata.archive,
            strict=strict, skip_elastic_fields=True)
        if metadata_error:
            raise Exception(metadata_error[1])

    # Check if this is a cart file to be decoded
    extracted_path, fileinfo, al_meta = decode_file(out_file, fileinfo, IDENTIFY)
    if extracted_path:
        try:
            # Remove the old out_file
            os.unlink(out_file)
        finally:
            # Replace it with the extracted path
            out_file = extracted_path

    # Alter filename and classification based on CaRT output
    if fileinfo["type"].startswith("uri/") and "uri_info" in fileinfo and "uri" in fileinfo["uri_info"]:
        al_meta["name"] = fileinfo["uri_info"]["uri"]

    meta_classification = al_meta.pop('classification', s_params['classification'])
    if meta_classification != s_params['classification']:
        try:
            s_params['classification'] = CLASSIFICATION.max_classification(meta_classification,
                                                                            s_params['classification'])
        except InvalidClassification as ic:
            raise Exception(f"The classification found inside the cart file cannot be merged with the classification the file was submitted as: {str(ic)}")
    name = al_meta.pop('name', name)
    metadata.update(al_meta)

    # Ensure a description is set on the submission (if not already)
    if not s_params.get('description'):
        s_params['description'] = f"Inspection of {'URL' if fileinfo['type'].startswith('uri/') else 'file'}: {name}"

    # Perform a series to input checks to make sure everything is valid before proceeding
    if not CLASSIFICATION.is_accessible(user['classification'], s_params['classification']):
        raise Exception("You cannot start a submission with higher classification then you're allowed to see")
    elif not name:
        # No filename given or derived
        raise Exception("Filename missing")

    # Return the file path, name, & information, validated submission parameters, and metadata (yet to be validated)
    return data, out_file, name, fileinfo, s_params, metadata


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

                        download_fileinfo = IDENTIFY.fileinfo(out_file, generate_hashes=False,
                                                              calculate_entropy=False,
                                                              skip_fuzzy_hashes=True)
                        if source.password and download_fileinfo['type'] == "archive/zip":
                            try:
                                # Determine the number of files contained and if it surpasses the maximum file size limit
                                zip_namelist = subprocess.run(["7zz", "l", "-ba", out_file], capture_output=True, text=True, check=True).stdout.splitlines()
                                if len(zip_namelist) == 1:
                                    # Check the size of the file and if it surpasses the maximum file size limit
                                    file_size = int(zip_namelist[0].split()[3])
                                    if file_size >= config.submission.max_file_size:
                                        raise FileTooBigException(file_size)
                                    else:
                                        # If the file is a zip file, we need to extract it using the provided password
                                        with tempfile.TemporaryDirectory() as extract_dir:
                                            try:
                                                # Extract the zip file to a temporary directory and replace the original file
                                                subprocess.run(["7zz", "e", f"-p{source.password}", "-y", f"-o{extract_dir}", out_file], capture_output=True, check=True)
                                                extracted_files = os.listdir(extract_dir)
                                                if extracted_files:
                                                    # Extraction was successful, replace the original file with the extracted one
                                                    os.replace(os.path.join(extract_dir, extracted_files[0]), out_file)
                                            except subprocess.CalledProcessError:
                                                # If the extraction fails, we can ignore it and keep the original file and let the extraction service handle it
                                                pass
                            except subprocess.CalledProcessError:
                                # If the 7zz command fails, we can ignore it and keep the original file and let the extraction service handle it
                                pass
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
                    if source.metadata:
                        # If a source has it's own metadata configuration, merge it with user's metadata
                        metadata.update(source.metadata)
                    else:
                        # Otherwise default to just providing the original source information
                        metadata['original_source'] = source.name

                    # Forcing service selection
                    for service in source.select_services:
                        if service not in s_params['services']['selected']:
                            s_params['services']['selected'].append(service)

                    # Check if the downloaded content has the same hash as the fetch method
                    if method in HASH_PATTERN_MAP and name == input:
                        hash = IDENTIFY.fileinfo(out_file, calculate_entropy=False)[method]
                        if hash != input:
                            # Rename the file to the hash of the downloaded content to avoid confusion
                            name = hash

                    # A source suited for the task was found, skip the rest
                    break


    return found, fileinfo, name

def update_submission_parameters(data: dict, user: dict, user_submission_profiles: dict) -> dict:
    s_profile = SUBMISSION_PROFILES.get(data.get('submission_profile'))
    submission_customize = ROLES.submission_customize in user['roles']

    s_params = {}
    if "submission_profile" in data:
        if not submission_customize and not s_profile:
            # If the profile specified doesn't exist, raise an exception
            raise Exception(f"Submission profile '{data['submission_profile']}' does not exist")
        else:
            # If the profile specified exists, get its parameters for the user settings as a base
            s_params = strip_nulls(user_submission_profiles.get(data['submission_profile'], {}))
    elif not submission_customize:
        # No profile specified, raise an exception back to the user
        raise Exception(f"You must specify a submission profile. One of: {list(SUBMISSION_PROFILES.keys())}")
    else:
        # No profile specified, use the default submission profile settings (legacy behaviour)
        s_params = strip_nulls(user_submission_profiles.get('default', {}))

    # Ensure classification is set based on the user before applying updates
    classification = s_params.get("classification", user['classification'])

    # Ensure any system-configured defaults are applied to parameters
    s_params.update({
        'groups': s_params['groups'] if 'groups' in s_params else \
            [g for g in user['groups'] if g in classification],
        'submitter': user['uname'],
        'ttl': int(s_params.get('ttl', config.submission.dtl))
    })

    # Apply the changes to the submission parameters based on the profile and user roles
    s_params = recursive_update(s_params, data.get("params", {}))
    if s_profile:
        if not CLASSIFICATION.is_accessible(user['classification'], s_profile.classification):
                # User isn't allowed to use the submission profile specified
                raise PermissionError(f"You aren't allowed to use '{s_profile.name}' submission profile")
        # Calculate the delta between the default settings and the user changes and apply it to the profile
        s_params = get_recursive_delta(DEFAULT_SUBMISSION_PROFILE_SETTINGS, s_params)
        s_params = apply_changes_to_profile(s_profile, s_params, user)

    # Apply final changes on top of the default submission settings
    s_params = recursive_update(deepcopy(DEFAULT_SUBMISSION_PROFILE_SETTINGS), s_params)

    # Ensure the classification exists in the resulting parameters
    s_params.setdefault("classification", classification)

    return s_params


def refang_url(url):
    '''
    Refangs a url of text. Based on source of: https://pypi.org/project/defang/
    '''
    new_url = re.sub(r'[\(\[\{](\.|dot)[\)\]\}]', '.', url, flags=re.IGNORECASE)
    new_url = re.sub(r'\\.', '.', new_url, flags=re.IGNORECASE)
    new_url = re.sub(r'[\(\[\{]/[\)\]\}]', '/', new_url, flags=re.IGNORECASE)
    new_url = re.sub(r'[\(\[\{]:[\)\]\}]', ':', new_url, flags=re.IGNORECASE)
    new_url = re.sub(r'[\(\[\{]://[\)\]\}]', '://', new_url, flags=re.IGNORECASE)
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
            raise FileTooBigException(file_size=r.headers['content-length'])

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
                        raise FileTooBigException(file_size=written)
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
