
from sys import exc_info
from traceback import format_tb

from flask import Blueprint, request, session
from werkzeug.exceptions import BadRequest, Forbidden, NotFound, Unauthorized

from assemblyline_ui.api.base import make_api_response
from assemblyline_ui.config import AUDIT, AUDIT_LOG, LOGGER, config
from assemblyline_ui.http_exceptions import (
    AccessDeniedException,
    AuthenticationException,
    InvalidDataException,
    NotFoundException,
)
from assemblyline_ui.logger import log_with_traceback

errors = Blueprint("errors", __name__)


######################################
# Custom Error page
@errors.app_errorhandler(400)
def handle_400(e):
    if isinstance(e, BadRequest):
        error_message = "No data block provided or data block not in JSON format.'"
    else:
        error_message = str(e)
    return make_api_response("", error_message, 400)


@errors.app_errorhandler(401)
def handle_401(e):
    if isinstance(e, Unauthorized):
        msg = e.description
    else:
        msg = str(e)

    data = {
        "oauth_providers": [name for name, p in config.auth.oauth.providers.items()
                            if p['client_id']] if config.auth.oauth.enabled else [],
        "allow_userpass_login": config.auth.ldap.enabled or config.auth.internal.enabled,
        "allow_signup": config.auth.internal.enabled and config.auth.internal.signup.enabled,
        "allow_saml_login": config.auth.saml.enabled,
    }
    session.clear()
    res = make_api_response(data, msg, 401)
    res.set_cookie('XSRF-TOKEN', '', max_age=0)
    return res


@errors.app_errorhandler(403)
def handle_403(e):
    if isinstance(e, Forbidden):
        error_message = e.description
    else:
        error_message = str(e)

    trace = exc_info()[2]
    if AUDIT:
        uname = "(None)"
        ip = session.get("ip", request.remote_addr)
        uname = session.get("username", uname)

        log_with_traceback(AUDIT_LOG, trace, f"Access Denied. (U:{uname} - IP:{ip}) [{error_message}]")

    config_block = {
        "auth": {
            "allow_2fa": config.auth.allow_2fa,
            "allow_apikeys": config.auth.allow_apikeys,
            "allow_security_tokens": config.auth.allow_security_tokens,
        },
        "ui": {
            "allow_url_submissions": config.ui.allow_url_submissions,
            "read_only": config.ui.read_only,
            "tos": config.ui.tos not in [None, ""],
            "tos_lockout": config.ui.tos_lockout,
            "tos_lockout_notify": config.ui.tos_lockout_notify not in [None, []]
        }
    }
    return make_api_response(config_block, "Access Denied (%s) [%s]" % (request.path, error_message), 403)


@errors.app_errorhandler(404)
def handle_404(e):
    if isinstance(e, NotFound):
        return make_api_response("", "Api does not exist (%s)" % request.path, 404)
    else:
        return make_api_response("", str(e), 400)


@errors.app_errorhandler(415)
def handle_415(e):
    return make_api_response("", str(e))


@errors.app_errorhandler(500)
def handle_500(e):
    if isinstance(e.original_exception, AccessDeniedException):
        return handle_403(e.original_exception)

    if isinstance(e.original_exception, AuthenticationException):
        return handle_401(e.original_exception)

    if isinstance(e.original_exception, InvalidDataException):
        return handle_400(e.original_exception)

    if isinstance(e.original_exception, NotFoundException):
        return handle_404(e.original_exception)

    oe = e.original_exception or e

    trace = exc_info()[2]
    log_with_traceback(LOGGER, trace, "Exception", is_exception=True)

    if config.ui.debug:
        message = ''.join(['\n'] + format_tb(exc_info()[2]) + ['%s: %s\n' % (oe.__class__.__name__, str(oe))]).rstrip('\n')
    else:
        message = "Internal Server Error"
    return make_api_response("", message, 500)
