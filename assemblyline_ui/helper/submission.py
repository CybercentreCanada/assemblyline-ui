import json
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


def validate_url(url):
    try:
        parsed = urlparse(url)
    except Exception:
        raise InvalidUrlException('Url provided is invalid.')

    host = parsed.hostname or parsed.netloc

    if host:
        try:
            cur_ip = socket.gethostbyname(host)
        except socket.gaierror:
            cur_ip = '127.0.0.1'

        if is_ip_reserved(cur_ip) or cur_ip == MYIP:
            raise ForbiddenLocation("Location '%s' cannot be resolved." % host)


def validate_redirect(r, **_):
    if r.is_redirect:
        location = safe_str(r.headers['location'])
        try:
            validate_url(location)
        except Exception:
            raise InvalidUrlException('Url provided is invalid.')


def download_from_url(download_url, target, data=None, method="GET",
                      headers={}, proxies={}, verify=True, validate=True, failure_pattern=None,
                      timeout=None):
    hooks = None
    if validate:
        validate_url(download_url)
        hooks = {'response': validate_redirect}

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

    r = session_function(download_url, data=data, hooks=hooks, headers=headers, proxies=proxies, stream=True,
                         timeout=timeout, allow_redirects=True)

    if r.ok:
        if int(r.headers.get('content-length', 0)) > config.submission.max_file_size:
            raise FileTooBigException("File too big to be scanned.")

        written = 0

        with open(target, 'wb') as f:
            for chunk in r.iter_content(chunk_size=512 * 1024):
                if chunk:  # filter out keep-alive new chunks
                    if failure_pattern and failure_pattern in chunk:
                        f.close()
                        os.unlink(target)
                        return None

                    written += 512 * 1024
                    if written > config.submission.max_file_size:
                        f.close()
                        os.unlink(target)
                        raise FileTooBigException("File too big to be scanned.")
                    f.write(chunk)

            if written > 0:
                return [r.url for r in r.history if r.url != download_url]

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
