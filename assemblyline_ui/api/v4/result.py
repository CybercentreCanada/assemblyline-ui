from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import MultiKeyError
from assemblyline.odm.models.user import ROLES
from flask import request

from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION, LOGGER, STORAGE
from assemblyline_ui.helper.result import format_result

SUB_API = 'result'
result_api = make_subapi_blueprint(SUB_API, api_version=4)
result_api._doc = "Manage the different services"


@result_api.route("/multiple_keys/", methods=["POST"])
@api_login(audit=False, require_role=[ROLES.submission_view])
def get_multiple_service_results(**kwargs):
    """
    Get multiple result and error keys at the same time

    Variables:
    None

    Arguments:
    None

    Data Block:
    {"error": [],      #List of error keys to lookup
     "result": []      #List of result keys to lookup
    }

    Result example:
    {"error": {},      #Dictionary of error object matching the keys
     "result": {}      #Dictionary of result object matching the keys
    }
    """
    user = kwargs['user']
    data = request.json

    index_type = Index.HOT
    if ROLES.archive_view in user['roles']:
        index_type = Index.HOT_AND_ARCHIVE

    try:
        errors = STORAGE.error.multiget(data.get('error', []), as_dictionary=True, as_obj=False, index_type=index_type)
    except MultiKeyError as e:
        LOGGER.warning(f"Trying to get multiple errors but some are missing: {str(e.keys)}")
        errors = e.partial_output
    results = STORAGE.get_multiple_results(data.get('result', []), CLASSIFICATION, as_obj=False, index_type=index_type)

    required_file_hashes = list(set([x[:64] for x in results.keys()]) | set([x[:64] for x in errors.keys()]))
    try:
        file_infos = STORAGE.file.multiget(required_file_hashes, as_dictionary=True, as_obj=False, index_type=index_type)
    except MultiKeyError as e:
        LOGGER.warning(f"Trying to get multiple files but some are missing: {str(e.keys)}")
        file_infos = e.partial_output

    for r_key in list(results.keys()):
        file_classification = file_infos.get(r_key[:64], {}).get('classification')
        if file_classification is None:
            LOGGER.error(f"File {r_key[:64]} referenced by result {r_key} does not exist in the system")
            del results[r_key]
            continue

        r_value = format_result(user['classification'], results[r_key],
                                file_classification,
                                build_hierarchy=True)
        if not r_value:
            del results[r_key]
        else:
            results[r_key] = r_value

    error_service_names = list(set(k.split('.')[1] for k in errors.keys() if '.' in k))
    error_services = {}
    for svc_name in error_service_names:
        svc = STORAGE.get_service_with_delta(svc_name, as_obj=False)
        if svc:
            error_services[svc_name] = svc

    for e_key in list(errors.keys()):
        file_classification = file_infos.get(e_key[:64], {}).get('classification')
        if file_classification is None:
            LOGGER.error(f"File {e_key[:64]} referenced by error {e_key} does not exist in the system")
            del errors[e_key]
            continue

        if not CLASSIFICATION.is_accessible(user['classification'], file_classification):
            del errors[e_key]
            continue

        svc_name = e_key.split('.')[1] if '.' in e_key else None
        if not svc_name:
            LOGGER.error(f"Error key {e_key} does not have a service name in it")
            del errors[e_key]
            continue

        svc = error_services.get(svc_name)
        if not svc:
            LOGGER.error(f"Service {svc_name} referenced by error {e_key} does not exist in the system")
            del errors[e_key]
            continue

        if not CLASSIFICATION.is_accessible(user['classification'], svc['classification']):
            del errors[e_key]

    out = {"error": errors, "result": results}

    return make_api_response(out)


@result_api.route("/error/<path:cache_key>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_service_error(cache_key, **kwargs):
    """
    Get the content off a given service error cache key.

    Variables:
    cache_key     => Service result cache key
                     as SHA256.ServiceName.ServiceVersion.Configuration.e

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"created": "1900-01-01T00:00:00Z",   # Time at which the error was created
     "response": {                        # Service Response
         "message": "Err message",           # Error Message
         "service_debug_info": "",           # Infromation about where the job was processed
         "service_name": "NSRL",             # Service Name
         "service_version": "",              # Service Version
         "status": "FAIL"}                   # Status
     "sha256": "123456...123456"}         # SHA256 of the files in error
    """
    user = kwargs['user']

    data = STORAGE.error.get(cache_key, as_obj=False)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    sha256 = cache_key[:64]
    # Only need to check the 'hot' index since errors are only stored in the hot index
    file_info = STORAGE.file.get(sha256, as_obj=False, index_type=Index.HOT)
    if not file_info:
        LOGGER.error(f"File {sha256} referenced by error {cache_key} does not exist in the system")
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    if not CLASSIFICATION.is_accessible(user['classification'], file_info['classification']):
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    service_name = cache_key.split('.')[1] if '.' in cache_key else None
    if not service_name:
        LOGGER.error(f"Cache key {cache_key} does not have a service name in it")
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    service = STORAGE.get_service_with_delta(service_name, as_obj=False)
    if not service:
        LOGGER.error(f"Service {service_name} referenced by error {cache_key} does not exist in the system")
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    if not CLASSIFICATION.is_accessible(user['classification'], service['classification']):
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    return make_api_response(data)


@result_api.route("/<path:cache_key>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_service_result(cache_key, **kwargs):
    """
    Get the result for a given service cache key.

    Variables:
    cache_key         => Service result cache key
                         as SHA256.ServiceName.ServiceVersion.Configuration

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"response": {                        # Service Response
       "milestones": {},                    # Timing object
       "supplementary": [],                 # Supplementary files
       "service_name": "Mcafee",            # Service Name
       "message": "",                       # Service error message
       "extracted": [],                     # Extracted files
       "service_version": "v0"},            # Service Version
     "result": {                          # Result objects
       "score": 1302,                       # Total score for the file
       "sections": [{                       # Result sections
         "body": "Text goes here",            # Body of the section (TEXT)
         "classification": "",                # Classification
         "links": [],                         # Links inside the section
         "title_text": "Title",               # Title of the section
         "depth": 0,                          # Depth (for Display purposes)
         "score": 500,                        # Section's score
         "body_format": null,                 # Body format
         "subsections": []                    # List of sub-sections
         }, ... ],
       "classification": "",                # Maximum classification for service
       "tags": [{                           # Generated Tags
         "usage": "IDENTIFICATION",           # Tag usage
         "value": "Tag Value",                # Tag value
         "type": "Tag Type",                  # Tag type
         "weight": 50,                        # Tag Weight
         "classification": ""                 # Tag Classification
         }, ...]
       }
    }
    """
    user = kwargs['user']
    index_type = Index.HOT
    if ROLES.archive_view in user['roles']:
        index_type = Index.HOT_AND_ARCHIVE

    data = STORAGE.get_single_result(cache_key, CLASSIFICATION, as_obj=False, index_type=index_type)

    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    cur_file = STORAGE.file.get(cache_key[:64], as_obj=False, index_type=index_type)
    if not cur_file:
        LOGGER.error(f"File {cache_key[:64]} referenced by result {cache_key} does not exist in the system")
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    data = format_result(user['classification'],
                         data,
                         cur_file.get('classification', CLASSIFICATION.UNRESTRICTED),
                         build_hierarchy=True)
    if not data:
        return make_api_response("", "You are not allowed to view the results for this key", 403)

    return make_api_response(data)
