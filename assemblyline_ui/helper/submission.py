import json
import re
import requests
import os
import socket

from urllib.parse import urlparse

from assemblyline.common.isotime import now_as_iso
from assemblyline.common.str_utils import safe_str
from assemblyline.common.iprange import is_ip_reserved
from assemblyline.odm.messages.submission import SubmissionMessage
from assemblyline_ui.config import STORAGE, CLASSIFICATION, SUBMISSION_TRAFFIC, config

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
            raise FileTooBigException("File too big to be scanned.")

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
        f"_i{config.submission.verdicts.info}"
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
