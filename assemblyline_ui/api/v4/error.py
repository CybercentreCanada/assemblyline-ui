
from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.user import ROLES
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE

SUB_API = 'error'
error_api = make_subapi_blueprint(SUB_API, api_version=4)
error_api._doc = "Perform operations on service errors"


@error_api.route("/<error_key>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_error(error_key, **kwargs):
    """
    Get the error details for a given error key

    Variables:
    error_key         => Error key to get the details for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        KEY: VALUE,   # All fields of an error in key/value pair
    }
    """
    user = kwargs['user']
    data = STORAGE.error.get(error_key, as_obj=False)

    if not user or not data:
        return make_api_response("", "The error was not found", 404)

    sha256 = error_key[:64]
    # Errors should pertain to files that are in the hot index, so we only check there
    file_info = STORAGE.file.get(sha256, as_obj=False, index_type=Index.HOT)
    if not file_info:
        LOGGER.error(f"File {sha256} referenced by error {error_key} does not exist in the system")
        return make_api_response("", "The error was not found", 404)

    if not CLASSIFICATION.is_accessible(user['classification'], file_info['classification']):
        return make_api_response("", "The error was not found", 404)

    service_name = error_key.split('.')[1] if '.' in error_key else None
    if not service_name:
        LOGGER.error(f"Error key {error_key} does not have a service name in it")
        return make_api_response("", "The error was not found", 404)

    service = STORAGE.get_service_with_delta(service_name, as_obj=False)
    if not service:
        LOGGER.error(f"Service {service_name} referenced by error {error_key} does not exist in the system")
        return make_api_response("", "The error was not found", 404)

    if not CLASSIFICATION.is_accessible(user['classification'], service['classification']):
        return make_api_response("", "The error was not found", 404)

    return make_api_response(data)


@error_api.route("/list/", methods=["GET"])
@api_login(require_role=[ROLES.administration], count_toward_quota=False)
def list_errors(**_):
    """
    List all error in the system (per page)

    Variables:
    None

    Arguments:
    offset            => Offset at which we start giving errors
    query             => Query to apply to the error list
    rows              => Numbers of errors to return
    sort              => Sort order
    track_total_hits  => Track the total number of item that match the query (Default: 10 000)

    Data Block:
    None

    Result example:
    {"total": 201,                # Total errors found
     "offset": 0,                 # Offset in the error list
     "count": 100,                # Number of errors returned
     "items": []                  # List of error blocks
    }
    """
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"
    filters = request.args.getlist('filters', None) or None
    sort = request.args.get('sort', "created desc")
    track_total_hits = request.args.get('track_total_hits', None)

    try:
        return make_api_response(STORAGE.error.search(query, offset=offset, rows=rows, as_obj=False,
                                                      sort=sort, track_total_hits=track_total_hits, filters=filters))
    except SearchException as e:
        return make_api_response("", f"The specified search query is not valid. ({e})", 400)
