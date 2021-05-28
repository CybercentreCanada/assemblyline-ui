from flask import Blueprint, abort, make_response

from assemblyline_ui.config import STORAGE

API_PREFIX = "/healthz"
healthz = Blueprint("healthz", __name__, url_prefix=API_PREFIX)


@healthz.route("/live")
def liveness(**_):
    """
    Check if the API is live

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    OK or FAIL
    """
    return make_response("OK")


@healthz.route("/ready")
def readyness(**_):
    """
    Check if the API is Ready

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    OK or FAIL
    """
    if STORAGE.ds.ping():
        return make_response("OK")
    else:
        abort(503)


@healthz.errorhandler(503)
def error(_):
    return "FAIL", 503
