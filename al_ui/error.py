
from flask import Blueprint, render_template, request, redirect
from sys import exc_info
from traceback import format_tb
from urllib.parse import quote

from al_ui.api.base import make_api_response
from al_ui.config import AUDIT, AUDIT_LOG, LOGGER, config
from al_ui.helper.views import redirect_helper
from al_ui.http_exceptions import AccessDeniedException, QuotaExceededException
from al_ui.logger import log_with_traceback

errors = Blueprint("errors", __name__)


######################################
# Custom Error page
@errors.app_errorhandler(400)
def handle_400(e):
    error_message = str(e)
    if request.path.startswith("/api/"):
        return make_api_response("", error_message, 400)
    else:
        return render_template('400.html'), 400


@errors.app_errorhandler(401)
def handle_401(_):
    if request.path.startswith("/api/"):
        return make_api_response("", "Authentication required", 401)
    else:
        return redirect(redirect_helper("/login.html?next=%s" % quote(request.full_path)))


@errors.app_errorhandler(404)
def handle_404(_):
    if request.path.startswith("/api/"):
        return make_api_response("", "Api does not exist (%s)" % request.path, 404)
    else:
        return render_template('404.html', url=request.path), 404


@errors.app_errorhandler(403)
def handle_403(e):
    error_message = str(e)
    trace = exc_info()[2]
    if AUDIT:
        log_with_traceback(AUDIT_LOG, trace, "Access Denied")

    if request.path.startswith("/api/"):
        return make_api_response("", "Access Denied (%s) [%s]" % (request.path, error_message), 403)
    else:
        if error_message.startswith("User") and str(e).endswith("is disabled"):
            return render_template('403e.html', exception=error_message,
                                   email=config.ui.get("email", "")), 403
        else:
            return render_template('403.html', exception=error_message), 403


@errors.app_errorhandler(500)
def handle_500(e):
    if isinstance(e, AccessDeniedException):
        return handle_403(e)

    if isinstance(e, QuotaExceededException):
        return make_api_response("", str(e), 503)

    trace = exc_info()[2]
    log_with_traceback(LOGGER, trace, "Exception", is_exception=True)

    message = ''.join(['\n'] + format_tb(exc_info()[2]) + ['%s: %s\n' % (e.__class__.__name__, str(e))]).rstrip('\n')
    if request.path.startswith("/api/"):
        return make_api_response("", message, 500)
    else:
        return render_template('500.html', exception=message), 500
