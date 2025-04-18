import time

from assemblyline_core.dispatching.client import DispatchClient
from flask import request
from werkzeug.exceptions import BadRequest

from assemblyline.datastore.collection import Index
from assemblyline.datastore.exceptions import MultiKeyError, SearchException
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.events import EventSender
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import AI_AGENT, CACHE, FILESTORE, LOGGER, STORAGE, config
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.ai.base import APIException, EmptyAIResponse
from assemblyline_ui.helper.result import cleanup_heuristic_sections, format_result
from assemblyline_ui.helper.submission import get_or_create_summary

SUB_API = 'submission'
submission_api = make_subapi_blueprint(SUB_API, api_version=4)
submission_api._doc = "Perform operations on system submissions"


HEUR_RANK_MAP = {
    'safe': 0,
    'info': 1,
    'suspicious': 2,
    'malicious': 3
}

event_sender = EventSender('delete',
                           host=config.core.redis.nonpersistent.host,
                           port=config.core.redis.nonpersistent.port)


@submission_api.route("/<sid>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.submission_delete])
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

    if submission['state'] != "completed":
        # Tell dispatcher to cancel submission if it is ongoing
        DispatchClient(datastore=STORAGE).cancel_submission(sid)

    if Classification.is_accessible(user['classification'], submission['classification']) \
            and (submission['params']['submitter'] == user['uname'] or ROLES.administration in user['roles']):
        STORAGE.delete_submission_tree_bulk(sid, Classification, transport=FILESTORE)
        STORAGE.submission.commit()
        event_sender.send("submission", sid)
        return make_api_response({"success": True})
    else:
        return make_api_response("", "Your are not allowed to delete this submission.", 403)


# noinspection PyBroadException
@submission_api.route("/<sid>/file/<sha256>/", methods=["GET", "POST"])
@api_login(require_role=[ROLES.submission_view])
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
            "classification": Classification.UNRESTRICTED,
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

        if request.method == "POST" and data['state'] != "completed":
            try:
                req_data = request.json
                extra_rkeys = req_data.get("extra_result_keys", [])
                extra_ekeys = req_data.get("extra_error_keys", [])
                # Load keys
                res_keys.extend(extra_rkeys)
                err_keys.extend(extra_ekeys)
            except BadRequest:
                pass

        res_keys = list(set(res_keys))
        err_keys = list(set(err_keys))

        # Get File, results and errors
        temp_file = STORAGE.file.get(sha256, as_obj=False)
        if not temp_file:
            output['file_info']['sha256'] = sha256
            output['signatures'] = list(output['signatures'])
            output['missing'] = True
            return make_api_response(output, "The file you are trying to view is missing from the system", 404)
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

        try:
            output['errors'] = STORAGE.error.multiget([x for x in err_keys if x.startswith(sha256)],
                                                      as_obj=False, as_dictionary=False)
        except MultiKeyError as e:
            LOGGER.warning(f"Trying to get multiple errors but some are missing: {str(e.keys)}")
            output['errors'] = e.partial_output

        output['metadata'] = STORAGE.get_file_submission_meta(sha256, config.ui.statistics.submission,
                                                              user["access_control"])

        done_heuristics = set()
        for res in output['results']:
            sorted_sections = sorted(res.get('result', {}).get('sections', []),
                                     key=lambda i: i['heuristic']['score'] if i['heuristic'] is not None else 0,
                                     reverse=True)
            for sec in sorted_sections:
                h_type = "info"
                if sec.get('heuristic', False):
                    # Get the heuristics data
                    if sec['heuristic']['score'] >= config.submission.verdicts.malicious:
                        h_type = "malicious"
                    elif sec['heuristic']['score'] >= config.submission.verdicts.suspicious:
                        h_type = "suspicious"
                    elif sec['heuristic']['score'] >= config.submission.verdicts.info:
                        h_type = "info"
                    else:
                        h_type = "safe"

                    if sec['heuristic']['heur_id'] not in done_heuristics:
                        item = (sec['heuristic']['heur_id'], sec['heuristic']['name'])
                        output['heuristics'].setdefault(h_type, [])
                        output['heuristics'][h_type].append(item)
                        done_heuristics.add(sec['heuristic']['heur_id'])

                    # Process Attack matrix
                    for attack in sec['heuristic'].get('attack', []):
                        attack_id = attack['attack_id']
                        for cat in attack['categories']:
                            output['attack_matrix'].setdefault(cat, [])
                            item = (attack_id, attack['pattern'], h_type)
                            if item not in output['attack_matrix'][cat]:
                                output['attack_matrix'][cat].append(item)

                    # Process Signatures
                    for signature in sec['heuristic'].get('signature', []):
                        sig = (signature['name'], h_type, signature.get('safe', False))
                        if sig not in output['signatures']:
                            output['signatures'].add(sig)

                # Process tags
                for t in sec['tags']:
                    output["tags"].setdefault(t['type'], {})
                    current_htype, _, _ = output["tags"][t['type']].get(t['value'], (None, None, None))
                    tag_htype = h_type
                    if current_htype:
                        if 'malicious' in (current_htype, h_type):
                            tag_htype = 'malicious'
                        elif 'suspicious' in (current_htype, h_type):
                            tag_htype = 'suspicious'
                        else:
                            tag_htype = 'info'
                    output["tags"][t['type']][t['value']] = (tag_htype, t['safelisted'], sec['classification'])

        for t_type in output["tags"]:
            output["tags"][t_type] = [(k, v[0], v[1], v[2]) for k, v in output['tags'][t_type].items()]

        output['signatures'] = list(output['signatures'])

        output['classification'] = max_c12n
        return make_api_response(output)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/tree/<sid>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
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
@api_login(require_role=[ROLES.submission_view])
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
        missing = []
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            try:
                err.update(STORAGE.error.multiget(keys, as_obj=False))
            except MultiKeyError as e:
                LOGGER.warning(f"Trying to get multiple errors but some are missing: {str(e.keys)}")
                err.update(e.partial_output)
                missing.extend(e.keys)
            keys = [x for x in keys if x not in err and x not in missing]
            retry += 1

        out["errors"] = err
        out["missing_error_keys"] = keys + missing

        return out

    def get_file_infos(keys):
        infos = {}
        missing = []
        retry = 0
        while keys and retry < max_retry:
            if retry:
                time.sleep(2 ** (retry - 7))
            try:
                infos.update(STORAGE.file.multiget(keys, as_obj=False))
            except MultiKeyError as e:
                LOGGER.warning(f"Trying to get multiple files but some are missing: {str(e.keys)}")
                infos.update(e.partial_output)
                missing.extend(e.keys)
            keys = [x for x in keys if x not in infos and x not in missing]
            retry += 1

        return infos, missing

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
        data['file_infos'], data['missing_file_keys'] = get_file_infos(recursive_flatten_tree(data['file_tree']))
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
@api_login(require_role=[ROLES.submission_view])
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


@submission_api.route("/ai/<sid>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def get_ai_summary(sid, **kwargs):
    """
    Have an AI LLM summarize the AssemblyLine output in plain english.

    Variables:
    sid         => Submission ID to summarize

    Arguments:
    archive_only   => Only use the archive data to generate the summary
    detailed       => Do you want the detailed output (Default: False)
    no_cache       => Caching for the output of this API will be disabled
    with_trace     => Should the AI call return the full trace of the conversation?
    lang           => Which language do you want the AI to respond in?

    Data Block:
    None

    Result example:
    {
      "content": < THE AI SUMMARY IN MARKDOWN FORMAT >,
      "truncated": false
    }


    """
    if not AI_AGENT.has_backends():
        return make_api_response({}, "AI Support is disabled on this system.", 400)

    archive_only = request.args.get('archive_only', 'false').lower() in ['true', '']
    detailed = request.args.get('detailed', 'false').lower() in ['true', '']
    no_cache = request.args.get('no_cache', 'false').lower() in ['true', '']
    lang = request.args.get('lang', 'english')
    with_trace = request.args.get('with_trace', 'false').lower() in ['true', '']

    index_type = None
    if archive_only:
        if not config.datastore.archive.enabled:
            return make_api_response({}, "Archive Support is disabled on this system.", 400)
        index_type = Index.ARCHIVE

    user = kwargs['user']

    if archive_only and ROLES.archive_view not in user['roles']:
        return make_api_response({}, "User is not allowed to view the archive", 403)

    # Create the cache key
    cache_key = CACHE.create_key(sid, user['classification'], index_type,
                                 archive_only, detailed, lang, with_trace, "submission")
    ai_summary = None
    if (not no_cache):
        # Get the summary from cache
        ai_summary = CACHE.get(cache_key)

    if not ai_summary:
        data = STORAGE.get_ai_formatted_submission_data(
            sid, user_classification=user['classification'],
            cl_engine=Classification, index_type=index_type)
        if data is None:
            return make_api_response("", "Submission ID %s does not exists." % sid, 404)

        try:
            if detailed:
                ai_summary = AI_AGENT.detailed_al_submission(data, lang=lang, with_trace=with_trace)
            else:
                ai_summary = AI_AGENT.summarized_al_submission(data, lang=lang, with_trace=with_trace)

            # Save to cache
            CACHE.set(cache_key, ai_summary)
        except (APIException, EmptyAIResponse) as e:
            return make_api_response("", str(e), 400)

    return make_api_response(ai_summary)


@submission_api.route("/summary/<sid>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
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

        summary = get_or_create_summary(sid, submission["results"], user['classification'],
                                        submission['state'] == "completed")
        tags = summary['tags']
        attack_matrix = summary['attack_matrix']
        heuristics = summary['heuristics']
        output['classification'] = summary['classification']
        output['filtered'] = summary['filtered']
        output['partial'] = summary['partial']
        output['heuristic_sections'] = cleanup_heuristic_sections(summary['heuristic_sections'])
        output['heuristic_name_map'] = summary['heuristic_name_map']

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

                for sig in item['signatures']:
                    sig_key = f"heuristic.signature__{sig}"
                    output['map'].setdefault(sig_key, [])

                    if sha256 not in output['map'][sig_key]:
                        output['map'][sig_key].append(sha256)

                    if sig_key not in output['map'][sha256]:
                        output['map'][sha256].append(sig_key)

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
            stype = output['tags'][summary_type]
            current_htype = stype.setdefault(t['type'], {}).get(t['value'], None)
            if not current_htype:
                stype[t['type']][t['value']] = (t['h_type'], t['safelisted'], t['classification'])
            elif HEUR_RANK_MAP[current_htype[0]] < HEUR_RANK_MAP[t['h_type']]:
                # When returning tag classification without context, the least restrictive should be used
                current_clsf = current_htype[2]
                min_clsf = Classification.min_classification(current_clsf, t['classification'])
                stype[t['type']][t['value']] = (t['h_type'], t['safelisted'], min_clsf)

        for summary_type in output['tags']:
            for t_type in output['tags'][summary_type]:
                output['tags'][summary_type][t_type] = [(k, v[0], v[1], v[2])
                                                        for k, v in output['tags'][summary_type][t_type].items()]

        return make_api_response(output)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


# noinspection PyUnusedLocal
@submission_api.route("/is_completed/<sid>/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.submission_view])
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
@api_login(require_role=[ROLES.submission_view])
def list_submissions_for_group(group, **kwargs):
    """
    List all submissions of a given group.

    Variables:
    None

    Arguments:
    offset            => Offset at which we start giving submissions
    rows              => Numbers of submissions to return
    query             => Query to filter to the submission list
    use_archive       => List submissions from archive as well (Default: False)
    archive_only      => Only access the Malware archive (Default: False)
    track_total_hits  => Track the total number of item that match the query (Default: 10 000)

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
    track_total_hits = request.args.get('track_total_hits', None)
    use_archive = request.args.get('use_archive', 'false').lower() in ['true', '']
    archive_only = request.args.get('archive_only', 'false').lower() in ['true', '']

    if archive_only:
        index_type = Index.ARCHIVE
    elif use_archive:
        index_type = Index.HOT_AND_ARCHIVE
    else:
        index_type = Index.HOT

    if (use_archive or archive_only) and ROLES.archive_view not in user['roles']:
        return make_api_response({}, "User is not allowed to view the archive", 403)

    if group == "ALL":
        group_query = "id:*"
    else:
        group_query = f"params.groups:{group}"
    try:
        return make_api_response(STORAGE.submission.search(group_query, offset=offset, rows=rows, filters=filters,
                                                           access_control=user['access_control'],
                                                           sort='times.submitted desc', as_obj=False,
                                                           index_type=index_type, track_total_hits=track_total_hits))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@submission_api.route("/list/user/<username>/", methods=["GET"])
@api_login(require_role=[ROLES.submission_view])
def list_submissions_for_user(username, **kwargs):
    """
    List all submissions of a given user.

    Variables:
    None

    Arguments:
    offset            => Offset at which we start giving submissions
    rows              => Numbers of submissions to return
    query             => Query to filter the submission list
    use_archive       => List submissions from archive as well (Default: False)
    archive_only      => Only access the Malware archive (Default: False)
    track_total_hits  => Track the total number of item that match the query (Default: 10 000)

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
    track_total_hits = request.args.get('track_total_hits', None)
    use_archive = request.args.get('use_archive', 'false').lower() in ['true', '']
    archive_only = request.args.get('archive_only', 'false').lower() in ['true', '']

    if archive_only:
        index_type = Index.ARCHIVE
    elif use_archive:
        index_type = Index.HOT_AND_ARCHIVE
    else:
        index_type = Index.HOT

    if (use_archive or archive_only) and ROLES.archive_view not in user['roles']:
        return make_api_response({}, "User is not allowed to view the archive", 403)

    if not STORAGE.user.exists(username):
        return make_api_response("", "User %s does not exists." % username, 404)

    try:
        return make_api_response(STORAGE.submission.search(f"params.submitter:{username}", offset=offset, rows=rows,
                                                           filters=query, access_control=user['access_control'],
                                                           sort='times.submitted desc', as_obj=False,
                                                           index_type=index_type, track_total_hits=track_total_hits))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@submission_api.route("/report/<submission_id>/", methods=["GET"])
@api_login(check_xsrf_token=False, require_role=[ROLES.submission_view])
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
        results = submission.pop('results', [])
        summary = get_or_create_summary(submission_id, results, user['classification'],
                                        submission['state'] == "completed")
        tags = [t for t in summary['tags'] if not t['safelisted']]

        attack_matrix = summary['attack_matrix']
        heuristics = summary['heuristics']
        submission['classification'] = Classification.max_classification(submission['classification'],
                                                                         summary['classification'])
        if summary['filtered']:
            submission['report_filtered'] = True

        if summary['partial']:
            submission['report_partial'] = True

        submission['heuristic_sections'] = cleanup_heuristic_sections(summary['heuristic_sections'])
        submission['heuristic_name_map'] = summary['heuristic_name_map']
        submission['attack_matrix'] = {}
        submission['heuristics'] = {}
        submission['tags'] = {}
        submission['promoted_sections'] = []

        # Process attack matrix
        for item in attack_matrix:
            sha256 = item['key'][:64]

            for cat in item['categories']:

                submission['attack_matrix'].setdefault(cat, {})
                submission['attack_matrix'][cat].setdefault(item['name'], {'h_type': item['h_type'], 'files': []})
                for name in name_map.get(sha256, [sha256]):
                    if (name, sha256) not in submission['attack_matrix'][cat][item['name']]['files']:
                        submission['attack_matrix'][cat][item['name']]['files'].append((name, sha256))
                    submission['important_files'].add(sha256)

        # Process heuristics
        for h_type, items in heuristics.items():
            submission['heuristics'].setdefault(h_type, {})
            for item in items:
                sha256 = item['key'][:64]
                submission['heuristics'][h_type].setdefault(item['name'], [])
                for name in name_map.get(sha256, [sha256]):
                    if (name, sha256) not in submission['heuristics'][h_type][item['name']]:
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
            if HEUR_RANK_MAP[submission['tags'][summary_type][t['type']][t['value']]['h_type']] < \
                    HEUR_RANK_MAP[t['h_type']]:
                submission['tags'][summary_type][t['type']][t['value']]['h_type'] = t['h_type']

            for name in name_map.get(sha256, [sha256]):
                if (name, sha256) not in submission['tags'][summary_type][t['type']][t['value']]['files']:
                    submission['tags'][summary_type][t['type']][t['value']]['files'].append((name, sha256))
                submission['important_files'].add(sha256)

        # Process important files
        submitted_sha256 = submission['files'][0]['sha256']
        submission["file_info"] = STORAGE.file.get(submitted_sha256, as_obj=False)
        if submitted_sha256 in submission['important_files']:
            submission['important_files'].remove(submitted_sha256)

        submission['important_files'] = list(submission['important_files'])

        # Process promoted sections
        keys = [x for x in list(results) if not x.endswith(".e") and x.startswith(submitted_sha256)]
        results = STORAGE.result.multiget(keys, as_dictionary=False, as_obj=False)

        for result in results:
            formatted_result = format_result(user['classification'], result,
                                             submission['classification'], build_hierarchy=True)
            if formatted_result and Classification.is_accessible(user['classification'],
                                                                 formatted_result['classification']):
                for section in formatted_result['result'].get('sections'):
                    if section.get('promote_to', None) is not None:
                        submission['promoted_sections'].append(section)

        return make_api_response(submission)
    else:
        return make_api_response("", "You are not allowed to view the data of this submission", 403)


@submission_api.route("/verdict/<submission_id>/<verdict>/", methods=["PUT"])
@api_login(audit=False, check_xsrf_token=False, require_role=[ROLES.submission_manage])
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
