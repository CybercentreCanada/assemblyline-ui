import requests
import os
import socket
from urllib.parse import urlparse

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.common.iprange import is_ip_reserved

config = forge.get_config()
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

    try:
        cur_ip = socket.gethostbyname(host)
    except socket.gaierror:
        cur_ip = '127.0.0.1'

    if is_ip_reserved(cur_ip) or cur_ip == MYIP:
        raise ForbiddenLocation("Location '%s' cannot be resolved." % host)


def validate_redirect(r, **_):
    if r.is_redirect:
        location = safe_str(r.headers['location'])
        validate_url(location)


def safe_download(download_url, target):
    validate_url(download_url)
    headers = config.ui.url_submission_headers
    proxies = config.ui.url_submission_proxies

    r = requests.get(download_url,
                     verify=False,
                     hooks={'response': validate_redirect},
                     headers=headers,
                     proxies=proxies)

    if int(r.headers.get('content-length', 0)) > config.submission.max_file_size:
        raise FileTooBigException("File too big to be scanned.")

    written = 0

    with open(target, 'wb') as f:
        for chunk in r.iter_content(chunk_size=512 * 1024):
            if chunk:  # filter out keep-alive new chunks
                written += 512 * 1024
                if written > config.submission.max_file_size:
                    f.close()
                    os.unlink(target)
                    raise FileTooBigException("File too big to be scanned.")
                f.write(chunk)
