
from flask import request

from assemblyline.common import forge
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from al_ui.helper.result import format_result

config = forge.get_config()

SUB_API = 'result'
result_api = make_subapi_blueprint(SUB_API, api_version=4)
result_api._doc = "Manage the different services"


@result_api.route("/multiple/keys/", methods=["POST"])
@api_login(audit=False, required_priv=['R'])
def get_multiple_service_keys(**kwargs):
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

    errors = STORAGE.get_errors_dict(data['error'])
    results = STORAGE.get_results_dict(data['result'])

    srls = list(set([x[:64] for x in results.keys()]))
    file_infos = STORAGE.get_files_dict(srls)
    for r_key in results.keys():
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
                     as (SRL.ServiceName)

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"response": {                   # Service Response
         "milestones": {},              # Timing object
         "supplementary": [],           # Supplementary files
         "status": "FAIL",              # Status
         "service_version": "",         # Service Version
         "service_name": "NSRL",        # Service Name
         "extracted": [],               # Extracted files
         "score": 0,                    # Service Score
         "message": "Err Message"},     # Error Message
     "result": []}                   # Result objets
    """
    data = STORAGE.get_error(cache_key)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    return make_api_response(data)


@result_api.route("/result/<path:cache_key>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_service_result(cache_key, **kwargs):
    """
    Get the result for a given service cache key.

    Variables:
    cache_key         => Service result cache key
                         as SRL.ServiceName.ServiceVersion.ConfigHash

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
    data = STORAGE.get_result(cache_key)
    if data is None:
        return make_api_response("", "Cache key %s does not exists." % cache_key, 404)

    cur_file = STORAGE.get_file(cache_key[:64])
    data = format_result(user['classification'], data, cur_file['classification'])
    if not data:
        return make_api_response("", "You are not allowed to view the results for this key", 403)

    return make_api_response(data)
