
import os
import requests

from flask import abort, make_response, request

from assemblyline_ui.api.base import api_login, make_subapi_blueprint
from assemblyline_ui.config import config


SUB_API = 'proxy'
proxy_api = make_subapi_blueprint(SUB_API, api_version=4)
proxy_api._doc = "Proxy API requests to another server adding some metadata"

DO_NOT_PROXY = {"authorization", "x-user", "x-apikey", "cookie", "host", "scheme", "server-port", "x-xsrf-token"}


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

    # Create URL
    url = os.path.join(srv_config.url, path)

    # Load up params if any
    params = "&".join([f"{k}={v}" for k, v in request.args.items()])
    if params:
        url = f"{url}?{params}"

    # Forward to the request to the new URL
    req_kwargs = {"headers": headers}
    if not srv_config.verify:
        req_kwargs['verify'] = False
    if request.data:
        req_kwargs['data'] = request.data
    resp = requests.request(request.method, url, **req_kwargs)

    # Return the response as is
    return make_response(resp.content, resp.status_code)
