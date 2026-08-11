import requests
import urllib

from flask import abort, make_response, request

from assemblyline_ui.api.base import api_login, make_subapi_blueprint
from assemblyline_ui.config import config


SUB_API = 'proxy'
proxy_api = make_subapi_blueprint(SUB_API, api_version=4)
proxy_api._doc = "Proxy API requests to another server adding some metadata"

DO_NOT_PROXY = {"authorization", "x-user", "x-apikey", "cookie", "host", "scheme", "server-port", "x-xsrf-token"}


def get_proxied_url(base_url, path):
    """Join path to base_url, ensuring the result cannot escape the configured server.

    Returns None if the resulting URL is not on the same scheme/host or not under
    the base URL's path prefix (e.g. absolute URLs or '../' escapes in path).
    """
    url = urllib.parse.urljoin(base_url, path)
    base = urllib.parse.urlparse(base_url)
    target = urllib.parse.urlparse(url)
    base_dir = base.path if base.path.endswith("/") else base.path.rsplit("/", 1)[0] + "/"
    if (target.scheme, target.netloc) != (base.scheme, base.netloc) or not target.path.startswith(base_dir):
        return None
    return url


@proxy_api.route("/<server>/<path:path>", methods=["GET", "POST", "PUT", "DELETE", "HEAD"])
@api_login(count_toward_quota=False)
def proxy(server, path, **kwargs):
    """
    Proxy the requests to a server configured in the config.yml file while adding
    headers to the request

    Variables:
    path       =>   Path to redirect to on the server
    server     =>   Server to redirect to

    Arguments:
    None

    Data Block:
    None

    Result example:
    <CONTENT of the proxied request>
    """
    # Check if proxied server exists
    if server not in config.ui.api_proxies:
        abort(404, f"There is no configuration for server: {server}")

    # Load user and server config
    user = kwargs['user']
    srv_config = config.ui.api_proxies[server]

    # Load current headers and replace headers with the configured headers
    headers = {k: v for k, v in request.headers.items() if k.lower() not in DO_NOT_PROXY}
    for header_cfg in srv_config.headers:
        if header_cfg.key:
            headers[header_cfg.name] = user[header_cfg.key]
        else:
            headers[header_cfg.name] = header_cfg.value

    # Create URL and make sure it cannot escape the configured server
    url = get_proxied_url(srv_config.url, path)
    if url is None:
        abort(400, "Proxied path is not relative to the configured server URL")

    # Forward the request to the new URL without following redirects so the
    # server cannot be bounced to another host, the client can follow them itself
    # This could happen in the case of a compromised upstream or an open-redirect
    req_kwargs = {"headers": headers, "params": request.args.to_dict(flat=False), "allow_redirects": False}
    if not srv_config.verify:
        req_kwargs['verify'] = False
    if request.data:
        req_kwargs['data'] = request.data
    resp = requests.request(request.method, url, **req_kwargs)

    # Return the response as is, keeping the location header so clients can follow redirects themselves
    response = make_response(resp.content, resp.status_code)
    if "location" in resp.headers:
        response.headers["Location"] = resp.headers["location"]
    return response
