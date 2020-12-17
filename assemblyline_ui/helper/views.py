import elasticapm
import functools
import json

from datetime import timedelta
from flask import redirect, render_template, request, abort, current_app, make_response
from functools import update_wrapper

from assemblyline_ui.security.authenticator import BaseSecurityRenderer
from assemblyline.common.forge import get_config
from assemblyline_ui.config import DEBUG, STORAGE, BUILD_MASTER, BUILD_LOWER, BUILD_NO, SYSTEM_TYPE, APP_NAME
from assemblyline_ui.helper.user import login, create_menu

config = get_config()


#######################################
# Views Helper functions
def redirect_helper(path):
    return f"{current_app.config['PREFERRED_URL_SCHEME']}://{request.host}{path}"


def angular_safe(value):
    if isinstance(value, str):
        return value.replace("\\", "\\\\").replace("{", "\\{").replace("}", "\\}").replace("'", "\\'")

    return value


# noinspection PyPep8Naming
class protected_renderer(BaseSecurityRenderer):
    def __init__(self, require_type=None, load_settings=False, audit=True, required_priv=None, allow_readonly=True):
        super().__init__(require_type, audit, required_priv, allow_readonly)

        self.load_settings = load_settings

    def extra_session_checks(self, session):
        if not set(self.required_priv).intersection(set(session.get("privileges", []))):
            abort(401)

    def __call__(self, func):
        @functools.wraps(func)
        def base(*args, **kwargs):
            self.test_readonly("Page")

            # Validate User-Agent
            UNK = "__UNKNOWN__"
            user_agent = request.environ.get("HTTP_USER_AGENT", UNK)
            if UNK == user_agent or "MSIE 8" in user_agent or "MSIE 9" in user_agent or "MSIE 7" in user_agent \
                    or "MSIE 6" in user_agent:
                return redirect(redirect_helper("/unsupported.html"))

            # Create Path
            path = f"{request.path}?{request.query_string.decode('UTF-8')}"

            # Login
            logged_in_uname = self.get_logged_in_user()

            user = login(logged_in_uname, path)
            self.test_require_type(user, "Url")

            self.audit_if_required(args, kwargs, logged_in_uname, user, func)

            # Dump Generic KWARGS
            kwargs['build'] = f"{BUILD_MASTER}.{BUILD_LOWER}.{BUILD_NO}"
            kwargs['user'] = user

            if config.core.metrics.apm_server.server_url is not None:
                elasticapm.set_user_context(username=user.get('name', None),
                                            email=user.get('email', None),
                                            user_id=user.get('uname', None))

            settings = STORAGE.user_settings.get(user['uname'], as_obj=False)

            if settings:
                if config.ui.ui4_path is not None:
                    if settings.get('ui4', False):
                        return redirect(redirect_helper(config.ui.ui4_path))
                    user['ui4_ask'] = settings.get('ui4_ask', True)
                else:
                    user['ui4_ask'] = settings.get('ui4_ask', False)
            else:
                user['ui4_ask'] = False
            user['ui4_allow'] = config.ui.ui4_path is not None

            kwargs['user_js'] = json.dumps(user)
            kwargs['debug'] = str(DEBUG).lower()
            kwargs['menu'] = create_menu(user, path)
            kwargs['avatar'] = STORAGE.user_avatar.get(user['uname'])
            kwargs['is_prod'] = SYSTEM_TYPE == "production"
            kwargs['is_readonly'] = config.ui.read_only

            if not request.path == "/terms.html":
                if not user.get('agrees_with_tos', False) and config.ui.tos is not None:
                    return redirect(redirect_helper("/terms.html"))
                if not settings and not request.path == "/settings.html":
                    return redirect(redirect_helper("/settings.html?forced"))

            if self.load_settings:
                kwargs['settings'] = json.dumps(settings)

            return func(*args, **kwargs)
        base.protected = True
        base.require_type = self.require_type
        base.audit = self.audit
        base.required_priv = self.required_priv
        base.allow_readonly = self.allow_readonly
        return base


# noinspection PyIncorrectDocstring
def crossdomain(origin=None, methods=None, headers=None, max_age=21600, attach_to_all=True, automatic_options=True):
    """This decorator can be use to allow a page to do cross domain XMLHttpRequests"""
    if methods is not None:
        methods = ", ".join(sorted(x.upper() for x in methods))
    if headers is not None and not isinstance(headers, str):
        headers = ', '.join(x.upper() for x in headers)
    if not isinstance(origin, str):
        origin = ', '.join(origin)
    if isinstance(max_age, timedelta):
        # noinspection PyUnresolvedReferences
        max_age = max_age.total_seconds()

    def get_methods():
        if methods is not None:
            return methods

        options_resp = current_app.make_default_options_response()
        return options_resp.headers['allow']

    def decorator(f):
        def wrapped_function(*args, **kwargs):
            if automatic_options and request.method == 'OPTIONS':
                resp = current_app.make_default_options_response()
            else:
                resp = make_response(f(*args, **kwargs))

            if not attach_to_all and request.method != 'OPTIONS':
                return resp

            h = resp.headers

            h['Access-Control-Allow-Origin'] = origin
            h['Access-Control-Allow-Methods'] = get_methods()
            h['Access-Control-Max-Age'] = str(max_age)
            if headers is not None:
                h['Access-Control-Allow-Headers'] = headers
            return resp

        f.provide_automatic_options = False
        return update_wrapper(wrapped_function, f)
    return decorator


def custom_render(template, **kwargs):
    return render_template(template, app_name=APP_NAME, base_template="base.html", **kwargs)
