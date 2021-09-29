
import elasticapm
import functools
import hashlib
import jwt

from flask import current_app, Blueprint, jsonify, make_response, request, session as flsk_session, Response, abort
from sys import exc_info
from traceback import format_tb

from assemblyline_ui.security.apikey_auth import validate_apikey
from assemblyline_ui.security.authenticator import BaseSecurityRenderer
from assemblyline_ui.config import LOGGER, QUOTA_TRACKER, STORAGE, SECRET_KEY, VERSION
from assemblyline_ui.helper.user import login
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.config import config
from assemblyline_ui.logger import log_with_traceback
from assemblyline.common.str_utils import safe_str

API_PREFIX = "/api"
api = Blueprint("api", __name__, url_prefix=API_PREFIX)

XSRF_ENABLED = True
SCOPES = {
    'r': ["R"],
    'w': ["W"],
    'rw': ["R", "W"],
}


def make_subapi_blueprint(name, api_version=4):
    """ Create a flask Blueprint for a subapi in a standard way. """
    return Blueprint(name, name, url_prefix='/'.join([API_PREFIX, f"v{api_version}", name]))


####################################
# API Helper func and decorators
# noinspection PyPep8Naming
class api_login(BaseSecurityRenderer):
    def __init__(self, require_type=None, username_key='username', audit=True, required_priv=None,
                 check_xsrf_token=XSRF_ENABLED, allow_readonly=True):
        super().__init__(require_type, audit, required_priv, allow_readonly)

        self.username_key = username_key
        self.check_xsrf_token = check_xsrf_token

    def auto_auth_check(self):
        apikey = request.environ.get('HTTP_X_APIKEY', None)
        uname = request.environ.get('HTTP_X_USER', None)

        if apikey is not None and uname is not None:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            with elasticapm.capture_span(name="@api_login:auto_auth_check()", span_type="authentication"):
                try:
                    # TODO: apikey_handler is slow to verify the password (bcrypt's fault)
                    #       We could fix this by saving the hash of the combinaison of the
                    #       APIkey and the username in an ExpiringSet and looking it up for
                    #       sub-sequent calls...
                    validated_user, priv = validate_apikey(uname, apikey, STORAGE)
                except AuthenticationException:
                    msg = "Invalid user or APIKey"
                    LOGGER.warning(f"Authentication failure. (U:{uname} - IP:{ip}) [{msg}]")
                    abort(401, msg)
                    return

                if validated_user:
                    LOGGER.info(f"Login successful. (U:{uname} - IP:{ip})")
                    if not set(self.required_priv).intersection(set(priv)):
                        abort(403, "The method you've used to login does not give you access to this API")
                        return

                    return validated_user

        return None

    def extra_session_checks(self, session):
        if not set(self.required_priv).intersection(set(session.get("privileges", []))):
            abort(403, "The method you've used to login does not give you access to this API")
            return

        if "E" in session.get("privileges", []) and self.check_xsrf_token and \
                session.get('xsrf_token', "") != request.environ.get('HTTP_X_XSRF_TOKEN',
                                                                     request.args.get("XSRF_TOKEN", "")):
            abort(403, "Invalid XSRF token")
            return

    def __call__(self, func):
        @functools.wraps(func)
        def base(*args, **kwargs):
            if 'user' in kwargs:
                if kwargs['user'].get('authenticated', False):
                    return func(*args, **kwargs)
                else:
                    abort(403, "Invalid pre-authenticated user")
                    return

            self.test_readonly("API")
            logged_in_uname = self.get_logged_in_user()
            impersonator = None

            # Impersonate
            authorization = request.environ.get("HTTP_AUTHORIZATION", None)
            if authorization:
                # noinspection PyBroadException
                try:
                    bearer_token = authorization.split(" ")[-1]
                    headers = jwt.get_unverified_header(bearer_token)
                    decoded = jwt.decode(bearer_token,
                                         hashlib.sha256(f"{SECRET_KEY}_{headers['token_id']}".encode()).hexdigest(),
                                         algorithms=[headers.get('alg', "HS256")])
                except Exception:
                    abort(400, "Malformed bearer token")
                    return

                target_user = STORAGE.user.get(headers['user'], as_obj=False)
                if target_user:
                    target_token = target_user.get('apps', {}).get(headers['token_id'], {})
                    if target_token == decoded and target_token['client_id'] == logged_in_uname:
                        impersonator = logged_in_uname
                        logged_in_uname = headers['user']
                        LOGGER.info(f"{impersonator} is impersonating {logged_in_uname} for query: {request.path}")

                        if not set(self.required_priv).intersection(set(SCOPES[decoded["scope"]])):
                            abort(403, "The method you've used to login does not give you access to this API")
                            return
                    else:
                        abort(403, "Invalid bearer token")
                        return
                else:
                    abort(404, "User not found")
                    return

            user = login(logged_in_uname)

            # Terms of Service
            if request.path not in ["/api/v4/help/tos/", "/api/v4/user/whoami/",
                                    f"/api/v4/user/tos/{logged_in_uname}/",
                                    "/api/v4/auth/logout/"] \
                    and not user.get('agrees_with_tos', False) and config.ui.tos is not None:
                abort(403, "Agree to Terms of Service before you can make any API calls")
                return

            self.test_require_type(user, "API")

            #############################################
            # Special username api query validation
            #
            #    If an API call requests a username, the username as to match
            #    the logged in user or the user has to be ADMIN
            #
            #    API that needs this special validation need to make sure their
            #    variable name for the username is as an optional parameter
            #    inside 'username_key'. Default: 'username'
            if self.username_key in kwargs:
                if kwargs[self.username_key] != user['uname'] \
                        and not kwargs[self.username_key] == "__global__" \
                        and not kwargs[self.username_key] == "__workflow__" \
                        and not kwargs[self.username_key].lower() == "__current__" \
                        and 'admin' not in user['type']:
                    return make_api_response({}, "Your username does not match requested username", 403)

            self.audit_if_required(args, kwargs, logged_in_uname, user, func, impersonator=impersonator)

            # Save user credential in user kwarg for future reference
            kwargs['user'] = user

            if config.core.metrics.apm_server.server_url is not None:
                elasticapm.set_user_context(username=user.get('name', None),
                                            email=user.get('email', None),
                                            user_id=user.get('uname', None))

            # Check current user quota
            quota_user = user['uname']

            flsk_session['quota_user'] = quota_user
            flsk_session['quota_set'] = True

            quota = user.get('api_quota', 10)
            if not QUOTA_TRACKER.begin(quota_user, quota):
                if config.ui.enforce_quota:
                    LOGGER.info(f"User {quota_user} was prevented from using the api due to exceeded quota.")
                    return make_api_response("", f"You've exceeded your maximum quota of {quota}", 503)
                else:
                    LOGGER.debug(f"Quota of {quota} exceeded for user {quota_user}.")
            else:
                LOGGER.debug(f"{quota_user}'s quota is under or equal its limit of {quota}")

            return func(*args, **kwargs)
        base.protected = True
        base.require_type = self.require_type
        base.audit = self.audit
        base.required_priv = self.required_priv
        base.check_xsrf_token = self.check_xsrf_token
        base.allow_readonly = self.allow_readonly
        return base


def make_api_response(data, err="", status_code=200, cookies=None) -> Response:
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    if type(err) is Exception:
        trace = exc_info()[2]
        err = ''.join(['\n'] + format_tb(trace) +
                      ['%s: %s\n' % (err.__class__.__name__, str(err))]).rstrip('\n')
        log_with_traceback(LOGGER, trace, "Exception", is_exception=True)

    resp = make_response(jsonify({"api_response": data,
                                  "api_error_message": err,
                                  "api_server_version": VERSION,
                                  "api_status_code": status_code}),
                         status_code)

    if isinstance(cookies, dict):
        for k, v in cookies.items():
            resp.set_cookie(k, v)

    return resp


def make_file_response(data, name, size, status_code=200, content_type="application/octet-stream"):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Length"] = size
    response.headers["Content-Disposition"] = 'attachment; filename="%s"' % safe_str(name)
    return response


def stream_file_response(reader, name, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    chunk_size = 65535

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data
        reader.close()

    headers = {"Content-Type": 'application/octet-stream',
               "Content-Length": size,
               "Content-Disposition": 'attachment; filename="%s"' % safe_str(name)}
    return Response(generate(), status=status_code, headers=headers)


def make_binary_response(data, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = 'application/octet-stream'
    response.headers["Content-Length"] = size
    return response


def stream_binary_response(reader, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    chunk_size = 4096

    def generate():
        reader.seek(0)
        while True:
            data = reader.read(chunk_size)
            if not data:
                break
            yield data

    return Response(generate(), status=status_code, mimetype='application/octet-stream')


#####################################
# API list API (API inception)
@api.route("/")
@api_login(audit=False, required_priv=['R', 'W'],
           require_type=["user", "signature_importer", "signature_manager", "admin"])
def api_version_list(**_):
    """
    List all available API versions.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    ["v1", "v2", "v3"]         #List of API versions available
    """
    api_list = []
    for rule in current_app.url_map.iter_rules():
        if rule.rule.startswith("/api/"):
            version = rule.rule[5:].split("/", 1)[0]
            if version not in api_list and version != '':
                # noinspection PyBroadException
                try:
                    int(version[1:])
                except Exception:
                    continue
                api_list.append(version)

    return make_api_response(api_list)


@api.route("/site_map/")
@api_login(require_type=['admin'], audit=False)
def site_map(**_):
    """
    Check if all pages have been protected by a login decorator

    Variables:
    None

    Arguments:
    unsafe_only                    => Only show unsafe pages

    Data Block:
    None

    Result example:
    [                                #List of pages dictionary containing...
     {"function": views.default,     #Function name
      "url": "/",                    #Url to page
      "protected": true,             #Is function login protected
      "require_type": false,         #List of user type allowed to view the page
      "methods": ["GET"]},           #Methods allowed to access the page
    ]
    """
    pages = []
    for rule in current_app.url_map.iter_rules():
        func = current_app.view_functions[rule.endpoint]
        methods = []
        for item in rule.methods:
            if item != "OPTIONS" and item != "HEAD":
                methods.append(item)
        protected = func.__dict__.get('protected', False)
        required_type = func.__dict__.get('require_type', ['user'])
        audit = func.__dict__.get('audit', False)
        priv = func.__dict__.get('required_priv', '')
        allow_readonly = func.__dict__.get('allow_readonly', True)
        if "/api/v4/" in rule.rule:
            prefix = "api.v4."
        else:
            prefix = ""

        if config.ui.read_only and not allow_readonly:
            continue

        if "unsafe_only" in request.args and protected:
            continue

        pages.append({"function": f"{prefix}{rule.endpoint.replace('apiv4.', '')}",
                      "url": rule.rule,
                      "methods": methods,
                      "protected": protected,
                      "required_type": required_type,
                      "audit": audit,
                      "req_priv": priv})

    return make_api_response(sorted(pages, key=lambda i: i['url']))
