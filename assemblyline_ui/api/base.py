
from urllib.parse import quote
import elasticapm
import functools
import hashlib
import jwt

from flask import current_app, Blueprint, jsonify, make_response, request, session as flsk_session, Response, abort
from sys import exc_info
from traceback import format_tb

from assemblyline_ui.security.apikey_auth import validate_apikey
from assemblyline_ui.security.authenticator import BaseSecurityRenderer
from assemblyline_ui.security.oauth_auth import validate_oauth_token
from assemblyline_ui.config import LOGGER, QUOTA_TRACKER, STORAGE, SECRET_KEY, VERSION, CLASSIFICATION, \
    DAILY_QUOTA_TRACKER, AUDIT_LOG, AUDIT_LOGIN
from assemblyline_ui.helper.user import login
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.config import config
from assemblyline_ui.logger import log_with_traceback
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.user import ROLES

API_PREFIX = "/api"
api = Blueprint("api", __name__, url_prefix=API_PREFIX)

XSRF_ENABLED = True


def make_subapi_blueprint(name, api_version=4):
    """ Create a flask Blueprint for a subapi in a standard way. """
    return Blueprint(name, name, url_prefix='/'.join([API_PREFIX, f"v{api_version}", name]))


####################################
# API Helper func and decorators
# noinspection PyPep8Naming
class api_login(BaseSecurityRenderer):
    def __init__(self, require_role=None, username_key='username', audit=True,
                 check_xsrf_token=XSRF_ENABLED, allow_readonly=True, count_toward_quota=True):
        super().__init__(require_role, audit, allow_readonly)

        self.username_key = username_key
        self.check_xsrf_token = check_xsrf_token
        self.count_toward_quota = count_toward_quota

    def auto_auth_check(self):
        apikey = request.environ.get('HTTP_X_APIKEY', None)
        uname = request.environ.get('HTTP_X_USER', None)

        if apikey is not None and uname is not None:
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            with elasticapm.capture_span(name="auto_auth_check", span_type="authentication"):
                try:
                    # TODO: apikey_handler is slow to verify the password (bcrypt's fault)
                    #       We could fix this by saving the hash of the combinaison of the
                    #       APIkey and the username in an ExpiringSet and looking it up for
                    #       sub-sequent calls...
                    validated_user, roles_limit = validate_apikey(uname, apikey, STORAGE)
                except AuthenticationException as ae:
                    login_logger = AUDIT_LOG if AUDIT_LOGIN else LOGGER
                    login_logger.warning(f"Authentication failure. (U:{uname} - IP:{ip}) [{str(ae)}]")
                    abort(401, str(ae))
                    return

                if validated_user:
                    login_logger = AUDIT_LOG if AUDIT_LOGIN else LOGGER
                    login_logger.info(f"Login successful. (U:{uname} - IP:{ip})")

                    return validated_user, roles_limit

        return None, None

    def extra_session_checks(self, session):
        if "roles_limit" not in session:
            abort(401, "Invalid session")

        if session.get("roles_limit", []) is None and self.check_xsrf_token and \
                session.get('xsrf_token', "") != request.environ.get('HTTP_X_XSRF_TOKEN',
                                                                     request.args.get("XSRF_TOKEN", "")):
            abort(403, "Invalid XSRF token")

    @elasticapm.capture_span(span_type='authentication')
    def parse_al_obo_token(self, bearer_token, roles_limit, impersonator):
        # noinspection PyBroadException
        try:
            headers = jwt.get_unverified_header(bearer_token)

            # Test token validity
            if 'token_id' not in headers or 'user' not in headers:
                raise AuthenticationException("This is not a valid AL OBO token - Missing data from the headers")

            # Try to decode token
            decoded = jwt.decode(bearer_token,
                                 hashlib.sha256(f"{SECRET_KEY}_{headers['token_id']}".encode()).hexdigest(),
                                 algorithms=["HS256"])
        except jwt.PyJWTError as e:
            raise AuthenticationException(f"Invalid OBO token - {str(e)}")

        target_user = STORAGE.user.get(headers['user'], as_obj=False)
        if target_user:
            target_token = target_user.get('apps', {}).get(headers['token_id'], {})
            if target_token != decoded:
                raise AuthenticationException("Invalid OBO token - Token ID does not match the token")

            if target_token['client_id'] != impersonator:
                raise AuthenticationException(f"Invalid OBO token - {impersonator} is not allowed to use this token")

            if roles_limit:
                roles_limit = [r for r in decoded['roles'] if r in roles_limit]
            else:
                roles_limit = decoded["roles"]

            return target_user, roles_limit
        else:
            raise AuthenticationException("User of the OBO token is not found")

    def __call__(self, func):
        @functools.wraps(func)
        def base(*args, **kwargs):
            with elasticapm.capture_span(name="assemblyline_ui.api.base.api_login", span_type="authentication"):
                if 'user' in kwargs:
                    if kwargs['user'].get('authenticated', False):
                        return func(*args, **kwargs)
                    else:
                        abort(403, "Invalid pre-authenticated user")

                self.test_readonly("API")
                logged_in_uname, roles_limit = self.get_logged_in_user()
                impersonator = None
                user = None

                # Impersonate
                authorization = request.environ.get("HTTP_AUTHORIZATION", None)
                if authorization:
                    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
                    impersonator = logged_in_uname
                    bearer_token = authorization.split(" ")[-1]
                    token_provider = request.environ.get("HTTP_X_TOKEN_PROVIDER", None)
                    if token_provider:
                        # Token has an associated provider, use it to validate the token
                        try:
                            user, token_roles_limit = validate_oauth_token(
                                bearer_token, token_provider, return_user=True)
                        except AuthenticationException as e:
                            LOGGER.warning(f"Authentication failure. (U:{logged_in_uname} - IP:{ip}) [{str(e)}]")
                            abort(403, str(e))

                        # Combine role limits
                        if roles_limit:
                            roles_limit = [r for r in token_roles_limit if r in roles_limit]
                        else:
                            roles_limit = token_roles_limit
                    else:
                        # Use the internal AL token validator
                        try:
                            user, roles_limit = self.parse_al_obo_token(bearer_token, roles_limit, impersonator)
                        except AuthenticationException as e:
                            LOGGER.warning(f"Authentication failure. (U:{logged_in_uname} - IP:{ip}) [{str(e)}]")
                            abort(403, str(e))

                    # Intersect impersonator and user classifications
                    impersonator_user = STORAGE.user.get(impersonator, as_obj=False)
                    user['classification'] = CLASSIFICATION.intersect_user_classification(
                        impersonator_user['classification'], user['classification'])

                    # Set currently logged in user
                    logged_in_uname = user['uname']
                    LOGGER.info(f"{impersonator} [{ip}] is impersonating "
                                f"{logged_in_uname} for query: {request.path}")

                user = login(logged_in_uname, roles_limit, user=user)

                # Terms of Service
                if request.path not in ["/api/v4/help/tos/", "/api/v4/user/whoami/",
                                        f"/api/v4/user/tos/{logged_in_uname}/",
                                        "/api/v4/auth/logout/"] \
                        and not user.get('agrees_with_tos', False) and config.ui.tos is not None:
                    abort(403, "Agree to Terms of Service before you can make any API calls")

                self.test_require_role(user, "API")

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
                            and ROLES.administration not in user['roles']:
                        return make_api_response({}, "Your username does not match requested username", 403)

                self.audit_if_required(args, kwargs, logged_in_uname, user, func, impersonator=impersonator)

                # Save user credential in user kwarg for future reference
                kwargs['user'] = user

                if config.core.metrics.apm_server.server_url is not None:
                    elasticapm.set_user_context(username=user.get('name', None),
                                                email=user.get('email', None),
                                                user_id=user.get('uname', None))

                if config.ui.enforce_quota:
                    # Prepare session for quotas
                    quota_user = user['uname']
                    flsk_session['quota_user'] = quota_user
                    flsk_session['quota_set'] = True

                    # Check current user quota
                    quota = user.get('api_quota')
                    if quota is None:
                        quota = config.ui.default_quotas.concurrent_api_calls
                    if quota != 0 and not QUOTA_TRACKER.begin(quota_user, quota):
                        LOGGER.info(f"User {quota_user} was prevented from using the api due to exceeded quota.")
                        return make_api_response(
                            "", f"You've exceeded your maximum concurrent API calls quota of {quota}", 503)

                    # Check daily quota
                    daily_quota = user.get('api_daily_quota')
                    if daily_quota is None:
                        daily_quota = config.ui.default_quotas.daily_api_calls
                    if daily_quota != 0 and self.count_toward_quota:
                        current_daily_quota = DAILY_QUOTA_TRACKER.increment_api(quota_user)
                        flsk_session['remaining_quota_api'] = max(daily_quota - current_daily_quota, 0)
                        if current_daily_quota > daily_quota:
                            LOGGER.info(f"User {quota_user} was prevented from using the api due to exceeded quota.")
                            return make_api_response(
                                "", f"You've exceeded your daily maximum API calls quota of {daily_quota}", 503)

            return func(*args, **kwargs)
        base.protected = True
        base.require_role = self.require_role
        base.audit = self.audit
        base.check_xsrf_token = self.check_xsrf_token
        base.allow_readonly = self.allow_readonly
        base.count_toward_quota = self.count_toward_quota
        return base


def get_response_headers():
    headers = {}

    # Add remaining API quota
    daily_quota_api = flsk_session.pop("remaining_quota_api", None)
    if daily_quota_api is not None:
        headers['x-remaining-quota-api'] = daily_quota_api

    # Add remaining submission quota
    daily_quota_submission = flsk_session.pop("remaining_quota_submission", None)
    if daily_quota_submission is not None:
        headers['x-remaining-quota-submission'] = daily_quota_submission

    return headers


def make_api_response(data, err="", status_code=200, cookies=None) -> Response:
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    if type(err) is Exception:
        trace = exc_info()[2]
        log_with_traceback(LOGGER, trace, "Exception", is_exception=True)
        if config.ui.debug:
            err = ''.join(['\n'] + format_tb(trace) +
                          ['%s: %s\n' % (err.__class__.__name__, str(err))]).rstrip('\n')
        else:
            err = "Internal Server Error"

    resp = make_response(jsonify({"api_response": data,
                                  "api_error_message": err,
                                  "api_server_version": VERSION,
                                  "api_status_code": status_code}),
                         status_code)

    if isinstance(cookies, dict):
        for k, v in cookies.items():
            resp.set_cookie(k, v)

    # Add extra headers
    resp.headers.update(get_response_headers())

    return resp


def make_file_response(data, name, size, status_code=200, content_type="application/octet-stream"):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    filename = f"UTF-8''{quote(safe_str(name), safe='')}"

    response = make_response(data, status_code)
    response.headers["Content-Type"] = content_type
    response.headers["Content-Length"] = size
    response.headers["Content-Disposition"] = f"attachment; filename=file.bin; filename*={filename}"

    # Add extra headers
    response.headers.update(get_response_headers())

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

    filename = f"UTF-8''{quote(safe_str(name), safe='')}"

    headers = {"Content-Type": 'application/octet-stream', "Content-Length": size,
               "Content-Disposition": f"attachment; filename=file.bin; filename*={filename}"}

    # Add extra headers
    headers.update(get_response_headers())

    return Response(generate(), status=status_code, headers=headers)


def make_binary_response(data, size, status_code=200):
    quota_user = flsk_session.pop("quota_user", None)
    quota_set = flsk_session.pop("quota_set", False)
    if quota_user and quota_set:
        QUOTA_TRACKER.end(quota_user)

    response = make_response(data, status_code)
    response.headers["Content-Type"] = 'application/octet-stream'
    response.headers["Content-Length"] = size

    # Add extra headers
    response.headers.update(get_response_headers())

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

    # Add extra headers
    headers = get_response_headers() or None

    return Response(generate(), status=status_code, mimetype='application/octet-stream', headers=headers)


#####################################
# API list API (API inception)
@api.route("/")
@api_login(audit=False, count_toward_quota=False)
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
@api_login(require_role=[ROLES.administration], audit=False, count_toward_quota=False)
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
      "require_role": false,         #List of user type allowed to view the page
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
        required_type = func.__dict__.get('require_role', [])
        audit = func.__dict__.get('audit', False)
        allow_readonly = func.__dict__.get('allow_readonly', True)
        count_towards_quota = func.__dict__.get('count_toward_quota', False)
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
                      "count_towards_quota": count_towards_quota})

    return make_api_response(sorted(pages, key=lambda i: i['url']))
