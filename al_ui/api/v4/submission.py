
import time

import json

from assemblyline.common.classification import InvalidClassification
from flask import request

from assemblyline.common import forge
from assemblyline.datastore import SearchException
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from al_ui.helper.result import format_result

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'submission'
submission_api = make_subapi_blueprint(SUB_API, api_version=4)
submission_api._doc = "Perform operations on system submissions"


@submission_api.route("/<sid>/", methods=["DELETE"])
@api_login(allow_readonly=False)
def delete_submission(sid, **kwargs):
    """
    INCOMPLETE
    Delete a submission as well as all related 
    files, results and errors
    
    Variables:
    sid         => Submission ID to be deleted
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {success: true}
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(sid, as_obj=False)

    if not submission:
        return make_api_response("", f"There are not submission with sid: {sid}", 404)

    if Classification.is_accessible(user['classification'], submission['classification']) \
            and (submission['params']['submitter'] == user['uname'] or user['is_admin']):
        with forge.get_filestore() as f_transport:
            STORAGE.delete_submission_tree(sid, Classification, transport=f_transport)
        STORAGE.submission.commit()
        return make_api_response({"success": True})
    else:
        return make_api_response("", "Your are not allowed to delete this submission.", 403)


# noinspection PyBroadException
@submission_api.route("/<sid>/file/<sha256>/", methods=["GET", "POST"])
@api_login(required_priv=['R'])
def get_file_submission_results(sid, sha256, **kwargs):
    """
    Get the all the results and errors of a specific file
    for a specific Submission ID
    
    Variables:
    sid         => Submission ID to get the result for
    sha256         => Resource locator to get the result for
    
    Arguments (POST only): 
    extra_result_keys   =>  List of extra result keys to get
    extra_error_keys    =>  List of extra error keys to get
    
    Data Block:
    None
    
    Result example:
    {"errors": [],    # List of error blocks 
     "file_info": {}, # File information block (md5, ...)
     "results": [],   # List of result blocks
     "tags": [] }     # List of generated tags
    """
    user = kwargs['user']
    
    # Check if submission exist
    data = STORAGE.submission.get(sid, as_obj=False)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        # Prepare output
        output = {"file_info": {}, "results": [], "tags": [], "errors": []}
        
        # Extra keys - This is a live mode optimisation
        res_keys = data.get("results", [])
        err_keys = data.get("errors", [])
            
        if request.method == "POST" and request.json is not None and data['state'] != "completed":
            extra_rkeys = request.json.get("extra_result_keys", [])
            extra_ekeys = request.json.get("extra_error_keys", [])
        
            # Load keys 
            res_keys.extend(extra_rkeys)
            err_keys.extend(extra_ekeys)
            
        res_keys = list(set(res_keys))
        err_keys = list(set(err_keys))
    
        # Get File, results and errors
        temp_file = STORAGE.file.get(sha256, as_obj=False)
        if not Classification.is_accessible(user['classification'], temp_file['classification']):
            return make_api_response("", "You are not allowed to view the data of this file", 403)
        output['file_info'] = temp_file

        temp_results = list(STORAGE.get_multiple_results([x for x in res_keys if x.startswith(sha256)],
                                                         cl_engine=Classification, as_obj=False).values())
        results = []
        for r in temp_results:
            r = format_result(user['classification'], r, temp_file['classification'])
            if r:
                results.append(r)
        output['results'] = results 

        output['errors'] = STORAGE.error.multiget([x for x in err_keys if x.startswith(sha256)],
                                                  as_obj=False, as_dictionary=False)
        output['metadata'] = STORAGE.get_file_submission_meta(sha256, config.ui.statistics.submission,
                                                              user["access_control"])
        
        # Generate tag list
        temp = {}
        for res in output['results']:
            try:
                if 'result' in res:
                    if 'tags' in res['result']:
                        temp.update({"__".join([v["type"], v['value']]): v for v in res['result']['tags']})
            except Exception:
                pass
        
        output["tags"] = list(temp.values())
        
        return make_api_response(output)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/tree/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_file_tree(sid, **kwargs):
    """
    Get the file hierarchy of a given Submission ID. This is
    an N deep recursive process but is limited to the max depth
    set in the system settings.
    
    Variables:
    sid         => Submission ID to get the tree for
    
    Arguments: 
    None
    
    Data Block:
    None

    API call example:
    /api/v4/submission/tree/12345678-1234-1234-1234-1234567890AB/
    
    Result example:
    {                                # Dictionary of file blocks
     "1f...11": {                    # File sha256 (sha256)
       "score": 923,                 # Score for the file
       "name": ["file.exe",...]      # List of possible names for the file
       "children": {...}             # Dictionary of children file blocks
       }, ...
  
    """
    user = kwargs['user']
    
    data = STORAGE.submission.get(sid, as_obj=False)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(STORAGE.get_or_create_file_tree(data, config.submission.max_extraction_depth))
    else: 
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/full/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_full_results(sid, **kwargs):
    """
    Get the full results for a given Submission ID. The difference
    between this and the get results API is that this one gets the
    actual values of the result and error keys instead of listing 
    the keys.
    
    Variables:
    sid         => Submission ID to get the full results for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"classification": "UNRESTRICTIED"  # Access control for the submission
     "error_count": 0,                  # Number of errors in this submission
     "errors": [],                      # List of error blocks (see Get Service Error)
     "file_count": 4,                   # Number of files in this submission
     "files": [                         # List of submitted files
       ["FNAME", "sha256"], ...],              # Each file = List of name/sha256
     "file_infos": {                    # Dictionary of fil info blocks
       "234...235": <<FILE_INFO>>,          # File in block
       ...},                                # Keyed by file's sha256
     "file_tree": {                     # File tree of the submission
       "333...7a3": {                       # File tree item
        "children": {},                         # Recursive children of file tree item
        "name": ["file.exe",...]                # List of possible names for the file
        "score": 0                              # Score of the file
       },, ...},                            # Keyed by file's sha256
     "missing_error_keys": [],          # Errors that could not be fetched from the datastore
     "missing_result_keys": [],         # Results that could not be fetched from the datastore
     "results": [],                     # List of Results Blocks (see Get Service Result)
     "services": {                      # Service Block
       "selected": ["mcafee"],              # List of selected services
       "params": {},                        # Service specific parameters
       "excluded": []                       # List of excluded services
       },
     "state": "completed",              # State of the submission
     "submission": {                    # Submission Block
       "profile": true,                     # Should keep stats about execution?
       "description": "",                   # Submission description
       "ttl": 30,                           # Submission days to live
       "ignore_filtering": false,           # Ignore filtering services?
       "priority": 1000,                    # Submission priority, higher = faster
       "ignore_cache": true,                # Force reprocess even is result exist?
       "groups": ["group", ...],            # List of groups with access
       "sid": "ab9...956",                  # Submission ID
       "submitter": "user",                 # Uname of the submitter
       "max_score": 1422, },                # Score of highest scoring file
     "times": {                         # Timing block
       "completed": "2014-...",             # Completed time
       "submitted": "2014-..."              # Submitted time
       }
    }
    """
    max_retry = 10

    def get_results(keys):
        out = {}
        res = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            res.update(STORAGE.get_multiple_results(keys, Classification, as_obj=False))
            keys = [x for x in keys if x not in res]
            retry += 1

        results = {}
        for k, v in res.items():
            file_info = data['file_infos'].get(k[:64], None)
            if file_info:
                v = format_result(user['classification'], v, file_info['classification'])
                if v:
                    results[k] = v

        out["results"] = results
        out["missing_result_keys"] = keys

        return out

    def get_errors(keys):
        out = {}
        err = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            err.update(STORAGE.error.multiget(keys, as_obj=False))
            keys = [x for x in err_keys if x not in err]
            retry += 1

        out["errors"] = err
        out["missing_error_keys"] = keys

        return out

    def get_file_infos(keys):
        infos = {}
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            infos.update(STORAGE.file.multiget(keys, as_obj=False))
            keys = [x for x in keys if x not in infos]
            retry += 1

        return infos

    def recursive_flatten_tree(tree):
        sha256s = []

        for key, val in tree.items():
            sha256s.extend(recursive_flatten_tree(val.get('children', {})))
            if key not in sha256s:
                sha256s.append(key)

        return list(set(sha256s))

    user = kwargs['user']
    data = STORAGE.submission.get(sid, as_obj=False)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        res_keys = data.get("results", [])
        err_keys = data.get("errors", [])

        data['file_tree'] = STORAGE.get_or_create_file_tree(data, config.submission.max_extraction_depth)
        data['file_infos'] = get_file_infos(recursive_flatten_tree(data['file_tree']))
        data.update(get_results(res_keys))
        data.update(get_errors(err_keys))

        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_submission(sid, **kwargs):
    """
    Get the submission details for a given Submission ID
    
    Variables:
    sid         => Submission ID to get the details for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"files": [                 # List of source files
       ["FNAME", "sha256"], ...],    # Each file = List of name/sha256
     "errors": [],              # List of error keys (sha256.ServiceName)
     "submission": {            # Submission Block
       "profile": true,           # Should keep stats about execution?
       "description": "",         # Submission description
       "ttl": 30,                 # Submission days to live
       "ignore_filtering": false, # Ignore filtering services? 
       "priority": 1000,          # Submission priority, higher = faster
       "ignore_cache": true,      # Force reprocess even is result exist?
       "groups": ["group", ...],  # List of groups with access   
       "sid": "ab9...956",        # Submission ID
       "submitter": "user",       # Uname of the submitter
       "max_score": 1422, },      # Score of highest scoring file
     "results": [],             # List of Results keys (sha256.ServiceName.Version.Config)
     "times": {                 # Timing block
       "completed": "2014-...",   # Completed time
       "submitted": "2014-..."    # Submitted time
       }, 
     "state": "completed",      # State of the submission
     "services": {              # Service Block
       "selected": ["mcafee"],    # List of selected services
       "params": {},              # Service specific parameters
       "excluded": []             # List of excluded services
       }
    }
    """
    user = kwargs['user']
    data = STORAGE.submission.get(sid, as_obj=False)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if data and user and Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response(data)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/summary/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_summary(sid, **kwargs):
    """
    Retrieve the executive summary of a given submission ID. This
    is a MAP of tags to sha256 combined with a list of generated Tags.
    
    Variables:
    sid         => Submission ID to get the summary for
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {"map": {                # Map of TAGS to sha256
       "TYPE__VAL": [          # Type and value of the tags
         "sha256"                   # List of related sha256s
         ...],
       "sha256": [                # sha256
         "TYPE__VAL"             # List of related type/value
         ...], ... } 
     "tags": {               # Dictionary of tags        
       "TYPE": {               # Type of tag
         "VALUE": {              # Value of the tag
           "usage": "",            # Usage
           "classification": ""    # Classification
           }, ...
         }, ...
    }
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(sid, as_obj=False)
    if submission is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if user and Classification.is_accessible(user['classification'], submission['classification']):
        output = {"map": {}, "tags": {}}
        tags_cache = STORAGE.submission_tags.get_if_exists(sid, as_obj=False)

        if not tags_cache:
            tags = STORAGE.get_tag_list_from_keys(submission["results"])
            tags_cache = {"tags": json.dumps(tags),
                          "expiry_ts": submission['expiry_ts']}
            STORAGE.submission_tags.save(sid, tags_cache)
        else:
            tags = json.loads(tags_cache['tags'])

        for t in tags:
            if t["type"] not in config.submission.summary_tag_types or t['value'] == "" \
                    or not Classification.is_accessible(user['classification'], t['classification']):
                continue

            sha256 = t["key"][:64]
            tag_key = t['type'] + "__" + t['value']

            # File map
            if tag_key not in output['map']:
                output['map'][tag_key] = []

            if sha256 not in output['map'][tag_key]:
                output['map'][tag_key].append(sha256)

            # Tag map
            if sha256 not in output['map']:
                output['map'][sha256] = []

            if sha256 not in output['map'][sha256]:
                output['map'][sha256].append(tag_key)

            # Tags
            if t['type'] not in output['tags']:
                output['tags'][t['type']] = {t['value']: {'classification': t['classification'],
                                                          'context': t['context']}}
            else:
                if t['value'] not in output['tags'][t['type']]:
                    output['tags'][t['type']][t['value']] = {'classification': t['classification'],
                                                             'context': t['context']}

        for t_type in output['tags']:
            new_tag_list = []
            for k, v in output['tags'][t_type].items():
                try:
                    new_tag_list.append(
                        {'value': k, 'classification': Classification.max_classification(v['classification'],
                                                                                         submission[
                                                                                             'classification']),
                         'context': v['context']}
                    )
                except InvalidClassification:
                    continue

            output['tags'][t_type] = new_tag_list

        return make_api_response(output)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


# noinspection PyUnusedLocal
@submission_api.route("/is_completed/<sid>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def is_submission_completed(sid, **kwargs):
    """
    Check if a submission is completed
    
    Variables:
    sid         =>  Submission ID to lookup
    
    Arguments: 
    None 
    
    Data Block:
    None
    
    Result example:
    True/False
    """
    data = STORAGE.submission.get(sid, as_obj=False)
    if data is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)

    return make_api_response(data["state"] == "completed")


@submission_api.route("/list/group/<group>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_submissions_for_group(group, **kwargs):
    """
    List all submissions of a given group.
    
    Variables:
    None
    
    Arguments: 
    offset       => Offset at which we start giving submissions
    rows         => Numbers of submissions to return
    query        => Query to filter to the submission list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total results found
     "offset": 0,                 # Offset in the result list
     "count": 100,                # Number of results returned
     "items": [                   # List of submissions
       {"submission": {             # Submission Block
          "description": "",          # Description of the submission
          "sid": "ad2...234",         # Submission ID
          "groups": "GROUP",          # Accessible groups
          "ttl": "30",                # Days to live
          "submitter": "user",        # ID of the submitter
          "max_score": "1422"},       # Max score of all files
        "times": {                  # Timing
          "submitted":                # Time submitted
            "2014-06-17T19:20:19Z"}, 
        "state": "completed"        # State of the submission
    }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    filters = request.args.get('query', None) or None
    
    if group == "ALL":
        group_query = "id:*"
    else:
        group_query = f"params.groups:{group}"
    try:
        return make_api_response(STORAGE.submission.search(group_query, offset=offset, rows=rows, filters=filters,
                                                           access_control=user['access_control'], as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@submission_api.route("/list/user/<username>/", methods=["GET"])
@api_login(required_priv=['R'])
def list_submissions_for_user(username, **kwargs):
    """
    List all submissions of a given user.
    
    Variables:
    None
    
    Arguments: 
    offset       => Offset at which we start giving submissions
    rows         => Numbers of submissions to return
    query        => Query to filter the submission list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total results found
     "offset": 0,                 # Offset in the result list
     "count": 100,                # Number of results returned
     "items": [                   # List of submissions
       {"submission": {             # Submission Block
          "description": "",          # Description of the submission
          "sid": "ad2...234",         # Submission ID
          "groups": "GROUP",          # Accessible groups
          "ttl": "30",                # Days to live
          "submitter": "user",        # ID of the submitter
          "max_score": "1422"},       # Max score of all files
        "times": {                  # Timing
          "submitted":                # Time submitted
            "2014-06-17T19:20:19Z"}, 
        "state": "completed"        # State of the submission
    }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', None) or None
    
    account = STORAGE.user.get(username)
    if not account: 
        return make_api_response("", "User %s does not exists." % username, 404)
        
    try:
        return make_api_response(STORAGE.submission.search(f"params.submitter:{username}", offset=offset, rows=rows,
                                                           filters=query, access_control=user['access_control'],
                                                           as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)
