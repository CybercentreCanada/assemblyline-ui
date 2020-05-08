import time

from flask import request

from assemblyline.common import forge
from assemblyline.common.attack_map import attack_map
from assemblyline.datastore import SearchException
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE
from assemblyline_ui.helper.result import format_result
from assemblyline_ui.helper.submission import get_or_create_summary

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'submission'
submission_api = make_subapi_blueprint(SUB_API, api_version=4)
submission_api._doc = "Perform operations on system submissions"


@submission_api.route("/<sid>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False)
def delete_submission(sid, **kwargs):
    """
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
            and (submission['params']['submitter'] == user['uname'] or 'admin' in user['type']):
        with forge.get_filestore() as f_transport:
            STORAGE.delete_submission_tree_bulk(sid, Classification, transport=f_transport)
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
        output = {
            "file_info": {},
            "results": [],
            "tags": {},
            "errors": [],
            "attack_matrix": {},
            'heuristics': {},
            "signatures": set()
        }
        
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
        max_c12n = output['file_info']['classification']

        temp_results = list(STORAGE.get_multiple_results([x for x in res_keys if x.startswith(sha256)],
                                                         cl_engine=Classification, as_obj=False).values())
        results = []
        for r in temp_results:
            r = format_result(user['classification'], r, temp_file['classification'], build_hierarchy=True)
            if r:
                max_c12n = Classification.max_classification(max_c12n, r['classification'])
                results.append(r)
        output['results'] = results 

        output['errors'] = STORAGE.error.multiget([x for x in err_keys if x.startswith(sha256)],
                                                  as_obj=False, as_dictionary=False)
        output['metadata'] = STORAGE.get_file_submission_meta(sha256, config.ui.statistics.submission,
                                                              user["access_control"])

        heuristics = STORAGE.get_all_heuristics()
        for res in output['results']:
            for sec in res['result']['sections']:
                h_type = "info"
                if sec.get('heuristic', False):
                    # Get the heuristics data
                    h = heuristics.get(sec['heuristic']['heur_id'], None)
                    if h is not None:
                        if sec['heuristic']['score'] < 100:
                            h_type = "info"
                        elif sec['heuristic']['score'] < 1000:
                            h_type = "suspicious"
                        else:
                            h_type = "malicious"

                        item = (h['heur_id'], h['name'])
                        output['heuristics'].setdefault(h_type, [])
                        if item not in output['heuristics'][h_type]:
                            output['heuristics'][h_type].append(item)
                    else:
                        # TODO: I need a logger because I need to report this
                        pass

                    # Process Attack matrix
                    for attack in sec['heuristic'].get('attack', []):
                        attack_id = attack['attack_id']
                        attack_pattern_def = attack_map.get(attack_id, {})
                        if attack_pattern_def:
                            for cat in attack_pattern_def['categories']:
                                output['attack_matrix'].setdefault(cat, [])
                                item = (attack_id, attack_pattern_def['name'], h_type)
                                if item not in output['attack_matrix'][cat]:
                                    output['attack_matrix'][cat].append(item)
                        else:
                            # TODO: I need a logger because I need to report this.
                            pass

                    # Process Signatures
                    for signature in sec['heuristic'].get('signature', []):
                        sig = (signature['name'], h_type)
                        if sig not in output['signatures']:
                            output['signatures'].add(sig)

                # Process tags
                for t in sec['tags']:
                    output["tags"].setdefault(t['type'], [])
                    t_item = (t['value'], h_type)
                    if t_item not in output["tags"][t['type']]:
                        output["tags"][t['type']].append(t_item)

        output['signatures'] = list(output['signatures'])

        output['file_info']['classification'] = max_c12n
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
        return make_api_response(STORAGE.get_or_create_file_tree(data, config.submission.max_extraction_depth,
                                                                 cl_engine=Classification,
                                                                 user_classification=user['classification']))
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

        data['file_tree'] = STORAGE.get_or_create_file_tree(data, config.submission.max_extraction_depth,
                                                            cl_engine=Classification,
                                                            user_classification=user['classification'])['tree']
        data['file_infos'] = get_file_infos(recursive_flatten_tree(data['file_tree']))
        data.update(get_results(res_keys))
        data.update(get_errors(err_keys))

        for r in data['results'].values():
            data['classification'] = Classification.max_classification(data['classification'], r['classification'])

        for f in data['file_infos'].values():
            data['classification'] = Classification.max_classification(data['classification'], f['classification'])

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


# noinspection PyTypeChecker,PyUnresolvedReferences
@submission_api.route("/summary/<sid>/", methods=["GET"])
@api_login(required_priv=['R'])
def get_summary(sid, **kwargs):
    """
    Retrieve the executive summary of a given submission ID. This
    is a MAP of tags to sha256 combined with a list of generated Tags by summary type.
    
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
       "attribution": {        # attribution tags
         "TYPE": [               # Type of tag
           "VALUE",                # Value of the tag
            ...
           ],...
         }, ...
       ),
       "behavior": {},         # behavior tags
       "ioc"" {}               # IOC tags
     },
     "attack_matrix": {      # Attack matrix dictionary
       "CATEGORY": [           # List of Attack pattern for a given category
          ("ATTACK_ID",          # Attack ID
           "PATTERN_NAME")       # Name of the Attack Pattern
        ... ],
        ...
     },
     "heuristics": {         # Heuristics dictionary
       "info": [               # Heuritics maliciousness level
          ("HEUR_ID",            # Heuristic ID
           "Heuristic name")     # Name of the heuristic
        ... ],
        ...
     }
    }
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(sid, as_obj=False)
    if submission is None:
        return make_api_response("", "Submission ID %s does not exists." % sid, 404)
    
    if user and Classification.is_accessible(user['classification'], submission['classification']):
        output = {
            "map": {},
            "tags": {
                'behavior': {},
                'attribution': {},
                'ioc': {}
            },
            "attack_matrix": {},
            "heuristics": {},
            "classification": Classification.UNRESTRICTED,
            "filtered": False
        }

        summary = get_or_create_summary(sid, submission["results"], user['classification'])
        tags = summary['tags']
        attack_matrix = summary['attack_matrix']
        heuristics = summary['heuristics']
        output['classification'] = summary['classification']
        output['filtered'] = summary['filtered']

        # Process attack matrix
        for item in attack_matrix:
            sha256 = item['key'][:64]
            attack_id = item['attack_id']

            for cat in item['categories']:
                key = f"attack_pattern__{attack_id}"
                output['map'].setdefault(sha256, [])
                output['map'].setdefault(key, [])

                if sha256 not in output['map'][key]:
                    output['map'][key].append(sha256)

                if key not in output['map'][sha256]:
                    output['map'][sha256].append(key)

                output['attack_matrix'].setdefault(cat, [])
                if (attack_id, item['name'], item['h_type']) not in output['attack_matrix'][cat]:
                    output['attack_matrix'][cat].append((attack_id, item['name'], item['h_type']))

        # Process heuristics
        for cat, items in heuristics.items():
            for item in items:
                sha256 = item['key'][:64]
                heur_id = item['heur_id']

                key = f"heuristic__{heur_id}"
                output['map'].setdefault(sha256, [])
                output['map'].setdefault(key, [])

                if sha256 not in output['map'][key]:
                    output['map'][key].append(sha256)

                if key not in output['map'][sha256]:
                    output['map'][sha256].append(key)

                output['heuristics'].setdefault(cat, [])
                if (heur_id, item['name']) not in output['heuristics'][cat]:
                    output['heuristics'][cat].append((heur_id, item['name']))

        # Process tags
        for t in tags:
            summary_type = None

            if t["type"] in config.submission.tag_types.behavior:
                summary_type = 'behavior'
            elif t["type"] in config.submission.tag_types.attribution:
                summary_type = 'attribution'
            elif t["type"] in config.submission.tag_types.ioc:
                summary_type = 'ioc'

            if t['value'] == "" or summary_type is None:
                continue

            sha256 = t["key"][:64]
            tag_key = f"{t['type']}__{t['value']}"

            # File map
            output['map'].setdefault(tag_key, [])
            if sha256 not in output['map'][tag_key]:
                output['map'][tag_key].append(sha256)

            # Tag map
            output['map'].setdefault(sha256, [])
            if sha256 not in output['map'][sha256]:
                output['map'][sha256].append(tag_key)

            # Tags
            output['tags'][summary_type].setdefault(t['type'], [])
            if (t['value'], t['h_type']) not in output['tags'][summary_type][t['type']]:
                output['tags'][summary_type][t['type']].append((t['value'], t['h_type']))

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
                                                           access_control=user['access_control'],
                                                           sort='times.submitted desc', as_obj=False))
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
                                                           sort='times.submitted desc', as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@submission_api.route("/report/<submission_id>/", methods=["GET"])
@api_login(audit=False, check_xsrf_token=False)
def get_report(submission_id, **kwargs):
    """
    Create a report for a submission based on its ID.

    Variables:
    submission_id   ->   ID of the submission to create the report for

    Arguments:
    None

    Data Block:
    None

    Result example:
    { <THE REPORT> }
    """
    user = kwargs['user']
    submission = STORAGE.submission.get(submission_id, as_obj=False)
    if submission is None:
        return make_api_response("", "Submission ID %s does not exists." % submission_id, 404)

    submission['important_files'] = set()
    submission['report_filtered'] = False

    if user and Classification.is_accessible(user['classification'], submission['classification']):
        if submission['state'] != 'completed':
            return make_api_response("", f"It is too early to generate the report. "
                                         f"Submission ID {submission_id} is incomplete.", 425)

        tree = STORAGE.get_or_create_file_tree(submission, config.submission.max_extraction_depth,
                                               cl_engine=Classification, user_classification=user['classification'])
        submission['file_tree'] = tree['tree']
        submission['classification'] = Classification.max_classification(submission['classification'],
                                                                         tree['classification'])
        if tree['filtered']:
            submission['report_filtered'] = True

        errors = submission.pop('errors', None)
        submission['params']['services']['errors'] = list(set([x.split('.')[1] for x in errors]))

        def recurse_get_names(data):
            output = {}
            for key, val in data.items():
                output.setdefault(key, [])

                for res_name in val['name']:
                    output[key].append(res_name)

                children = recurse_get_names(val['children'])
                for c_key, c_names in children.items():
                    output.setdefault(c_key, [])
                    output[c_key].extend(c_names)

            return output

        name_map = recurse_get_names(tree['tree'])

        summary = get_or_create_summary(submission_id, submission.pop('results', []), user['classification'])
        tags = summary['tags']
        attack_matrix = summary['attack_matrix']
        heuristics = summary['heuristics']
        submission['classification'] = Classification.max_classification(submission['classification'],
                                                                         summary['classification'])
        if summary['filtered']:
            submission['report_filtered'] = True

        submission['attack_matrix'] = {}
        submission['heuristics'] = {}
        submission['tags'] = {}

        # Process attack matrix
        for item in attack_matrix:
            sha256 = item['key'][:64]

            for cat in item['categories']:

                submission['attack_matrix'].setdefault(cat, {})
                submission['attack_matrix'][cat].setdefault(item['name'], {'h_type': item['h_type'], 'files': []})
                for name in name_map.get(sha256, [sha256]):
                    submission['attack_matrix'][cat][item['name']]['files'].append((name, sha256))
                    submission['important_files'].add(sha256)

        # Process heuristics
        for h_type, items in heuristics.items():
            submission['heuristics'].setdefault(h_type, {})
            for item in items:
                sha256 = item['key'][:64]
                submission['heuristics'][h_type].setdefault(item['name'], [])
                for name in name_map.get(sha256, [sha256]):
                    submission['heuristics'][h_type][item['name']].append((name, sha256))
                    submission['important_files'].add(sha256)

        # Process tags
        for t in tags:
            summary_type = None

            if t["type"] in config.submission.tag_types.behavior:
                summary_type = 'behaviors'
            elif t["type"] in config.submission.tag_types.attribution:
                summary_type = 'attributions'
            elif t["type"] in config.submission.tag_types.ioc:
                summary_type = 'indicators_of_compromise'

            if t['value'] == "" or summary_type is None:
                continue

            sha256 = t["key"][:64]

            # Tags
            submission['tags'].setdefault(summary_type, {})
            submission['tags'][summary_type].setdefault(t['type'], {})
            submission['tags'][summary_type][t['type']].setdefault(t['value'], {'h_type': t['h_type'], 'files': []})
            for name in name_map.get(sha256, [sha256]):
                submission['tags'][summary_type][t['type']][t['value']]['files'].append((name, sha256))
                submission['important_files'].add(sha256)

        submitted_sha256 = submission['files'][0]['sha256']
        submission["file_info"] = STORAGE.file.get(submitted_sha256, as_obj=False)
        if submitted_sha256 in submission['important_files']:
            submission['important_files'].remove(submitted_sha256)

        submission['important_files'] = list(submission['important_files'])

        return make_api_response(submission)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/verdict/<submission_id>/<verdict>/", methods=["PUT"])
@api_login(audit=False, check_xsrf_token=False)
def set_verdict(submission_id, verdict, **kwargs):
    """
    Set the verdict of a submission based on its ID.

    Variables:
    submission_id   ->   ID of the submission to give a verdict to
    verdict         ->   verdict that the user think the submission is: malicious or non_malicious

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}   # Has the verdict been set or not
    """
    reverse_verdict = {
        'malicious': 'non_malicious',
        'non_malicious': 'malicious'
    }

    user = kwargs['user']

    if verdict not in ['malicious', 'non_malicious']:
        return make_api_response({"success": False}, f"'{verdict}' is not a valid verdict.", 400)

    document = STORAGE.submission.get(submission_id, as_obj=False)

    if not document:
        return make_api_response({"success": False}, f"There are no submission with id: {submission_id}", 404)

    if not Classification.is_accessible(user['classification'], document['classification']):
        return make_api_response({"success": False}, "You are not allowed to give verdict on submission with "
                                                     f"ID: {submission_id}", 403)

    resp = STORAGE.submission.update(submission_id, [
        ('REMOVE', f'verdict.{verdict}', user['uname']),
        ('APPEND', f'verdict.{verdict}', user['uname']),
        ('REMOVE', f'verdict.{reverse_verdict[verdict]}', user['uname'])
    ])

    propagate_resp = STORAGE.alert.update_by_query(f"sid:{submission_id}", [
        ('REMOVE', f'verdict.{verdict}', user['uname']),
        ('APPEND', f'verdict.{verdict}', user['uname']),
        ('REMOVE', f'verdict.{reverse_verdict[verdict]}', user['uname'])
    ])

    return make_api_response({"success": resp and propagate_resp is not False})
