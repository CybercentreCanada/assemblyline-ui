
from flask import request

from assemblyline.common import forge
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, CLASSIFICATION
from assemblyline_ui.helper.result import format_result

config = forge.get_config()

SUB_API = 'result'
result_api = make_subapi_blueprint(SUB_API, api_version=4)
result_api._doc = "Manage the different services"


@result_api.route("/multiple_keys/", methods=["POST"])
@api_login(audit=False, required_priv=['R'])
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

    errors = STORAGE.error.multiget(data.get('error', []), as_dictionary=True, as_obj=False)
    results = STORAGE.get_multiple_results(data.get('result', []), CLASSIFICATION, as_obj=False)

    file_infos = STORAGE.file.multiget(list(set([x[:64] for x in results.keys()])), as_dictionary=True, as_obj=False)
    for r_key in list(results.keys()):
        r_value = format_result(user['classification'], results[r_key], file_infos[r_key[:64]]['classification'])
        if not r_value:
            del results[r_key]
        else:
            results[r_key] = r_value

    out = {"error": errors, "result": results}

    return make_api_response(out)


@result_api.route("/error/<path:cache_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_service_error(cache_key, **_):
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
    data = STORAGE.error.get(cache_key, as_obj=False)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    return make_api_response(data)


@result_api.route("/<path:cache_key>/", methods=["GET"])
@api_login(required_priv=['R'])
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

    data = STORAGE.get_single_result(cache_key, CLASSIFICATION, as_obj=False)

    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    cur_file = STORAGE.file.get(cache_key[:64], as_obj=False)
    data = format_result(user['classification'], data, cur_file['classification'], build_hierarchy=True)
    if not data:
        return make_api_response("", "You are not allowed to view the results for this key", 403)

    return make_api_response(data)
