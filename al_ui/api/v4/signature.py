import concurrent.futures

from flask import request
from hashlib import sha256
from textwrap import dedent

from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch, now_as_iso
from assemblyline.common.yara import YaraParser
from assemblyline.datastore import SearchException
from assemblyline.odm.models.signature import DEPLOYED_STATUSES, STALE_STATUSES, DRAFT_STATUSES, VALID_GROUPS
from assemblyline.remote.datatypes.lock import Lock
from al_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from al_ui.config import LOGGER, STORAGE, ORGANISATION


Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'signature'
signature_api = make_subapi_blueprint(SUB_API, api_version=4)
signature_api._doc = "Perform operations on signatures"

DEFAULT_CACHE_TTL = 24 * 60 * 60  # 1 Day


@signature_api.route("/add/", methods=["PUT"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False)
def add_signature(**kwargs):
    """
    Add a signature to the system and assigns it a new ID
        WARNING: If two person call this method at exactly the
                 same time, they might get the same ID.
       
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    
    Result example:
    {"success": true,      #If saving the rule was a success or not
     "sid": "0000000000",  #SID that the rule was assigned
     "rev": 2 }            #Revision number at which the rule was saved.
    """
    user = kwargs['user']
    data = request.json

    # Check if organisation matches
    data_org = data.get("meta", {}).get("organisation", None)
    if data_org != ORGANISATION:
        return make_api_response("", f"The organisation provided does not match your organisation. "
                                     f"({data_org} != {ORGANISATION})", 400)

    if not Classification.is_accessible(user['classification'], data['meta'].get('classification',
                                                                                 Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    # Check signature type
    if not user['is_admin'] and "global" in data['type']:
        return make_api_response("", "Only admins are allowed to add global signatures.", 403)

    # Compute signature ID and Revision
    new_id = STORAGE.get_signature_last_id(ORGANISATION) + 1
    sid = "%s_%06d" % (ORGANISATION, new_id)
    data['meta']['rule_id'] = sid
    data['meta']['rule_version'] = 1
    key = f"{sid}r.{data['meta']['rule_version']}"

    # Set last saved by
    if "meta_extra" not in data:
        data['meta_extra'] = {'last_saved_by': user['uname']}
    else:
        data['meta_extra']['last_saved_by'] = user['uname']

    # Get rule dependancies
    yara_version = data['meta'].get('yara_version', None)
    data['depends'], data['modules'] = YaraParser.parse_dependencies(data['condition'],
                                                                     YaraParser.YARA_MODULES.get(yara_version, None))

    # Validate rule
    res = YaraParser.validate_rule(data)
    if res['valid']:
        # Test signature name
        other = STORAGE.signature.search(f"name:{data['name']} AND NOT id:{sid}*", fl='id', rows='0')
        if other['total'] > 0:
            return make_api_response(
                {"success": False},
                "A signature with that name already exists",
                400
            )

        # Add signature test warnings
        data['warning'] = res.get('warning', None)

        # Save the signature
        return make_api_response({"success": STORAGE.signature.save(key, data),
                                  "sid": data['meta']['rule_id'],
                                  "rev": int(data['meta']['rule_version'])})
    else:
        return make_api_response({"success": False}, res, 400)


# noinspection PyPep8Naming
@signature_api.route("/change_status/<sid>/<rev>/<status>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_status(sid, rev, status, **kwargs):
    """
    Change the status of a signature
       
    Variables:
    sid    =>  ID of the signature
    rev    =>  Revision number of the signature
    status  =>  New state
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { "success" : true }      #If saving the rule was a success or not
    """
    user = kwargs['user']
    possible_statuses = DEPLOYED_STATUSES + DRAFT_STATUSES
    if status not in possible_statuses:
        return make_api_response("",
                                 f"You cannot apply the status {status} on yara rules.",
                                 403)
    if not user['is_admin'] and status in DEPLOYED_STATUSES:
        return make_api_response("",
                                 "Only admins are allowed to change the signature status to a deployed status.",
                                 403)
    
    key = f"{sid}r.{rev}"
    data = STORAGE.signature.get(key, as_obj=False)
    if data:
        if not Classification.is_accessible(user['classification'], data['meta'].get('classification',
                                                                                     Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        if data['meta']['al_status'] in STALE_STATUSES and status not in DRAFT_STATUSES:
            return make_api_response("",
                                     f"Only action available while signature in {data['meta']['al_status']} "
                                     f"status is to change signature to a DRAFT status. ({', '.join(DRAFT_STATUSES)})",
                                     403)

        if data['meta']['al_status'] in DEPLOYED_STATUSES and status in DRAFT_STATUSES:
            return make_api_response("",
                                     f"You cannot change the status of signature {sid} r.{rev} from "
                                     f"{data['meta']['al_status']} to {status}.", 403)

        query = "meta.al_status:{status} AND id:{sid}* AND NOT id:{key}"
        today = now_as_iso()
        uname = user['uname']

        if status not in ['DISABLED', 'INVALID', 'TESTING']:
            keys = [k['id']
                    for k in STORAGE.signature.search(query.format(key=key, sid=sid, status=status),
                                                      fl="id", as_obj=False)['items']]
            for other in STORAGE.signature.multiget(keys, as_obj=False, as_dictionary=False):
                other['meta_extra']['al_state_change_date'] = today
                other['meta_extra']['al_state_change_user'] = uname
                other['meta']['al_status'] = 'DISABLED'

                STORAGE.signature.save(f"{other['meta']['rule_id']}r.{other['meta']['rule_version']}", other)

        data['meta_extra']['al_state_change_date'] = today
        data['meta_extra']['al_state_change_user'] = uname
        data['meta']['al_status'] = status

        return make_api_response({"success": STORAGE.signature.save(key, data)})
    else:
        return make_api_response("", f"Signature not found. ({sid} r.{rev})", 404)


@signature_api.route("/<sid>/<rev>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False, require_admin=True)
def delete_signature(sid, rev, **kwargs):
    """
    Delete a signature based of its ID and revision

    Variables:
    sid    =>     Signature ID
    rev    =>     Signature revision number

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}  # Signature delete successful
    """
    user = kwargs['user']
    data = STORAGE.signature.get(f"{sid}r.{rev}", as_obj=False)
    if data:
        if not Classification.is_accessible(user['classification'],
                                            data['meta'].get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to delete this signature.", 403)
        return make_api_response({"success": STORAGE.signature.delete(f"{sid}r.{rev}")})
    else:
        return make_api_response("", f"Signature not found. ({sid} r.{rev})", 404)


# noinspection PyBroadException
def _get_cached_signatures(signature_cache, query_hash):
    try:
        s = signature_cache.get(query_hash)
        if s is None:
            return s
        return make_file_response(
            s, f"al_yara_signatures_{query_hash[:7]}.yar", len(s), content_type="text/yara"
        )
    except Exception:  # pylint: disable=W0702
        LOGGER.exception('Failed to read cached signatures:')

    return None


@signature_api.route("/download/", methods=["GET"])
@api_login(required_priv=['R'], check_xsrf_token=False, allow_readonly=False)
def download_signatures(**kwargs):
    """
    Download signatures from the system.
    
    Variables:
    None 
    
    Arguments: 
    query       => SOLR query to filter the signatures
                   Default: All deployed signatures
    safe        => Get a ruleset that will work in yara
                   Default: False
    
    Data Block:
    None
    
    Result example:
    <A .YAR SIGNATURE FILE>
    """
    user = kwargs['user']
    query = request.args.get('query', 'meta.al_status:DEPLOYED')
    safe = request.args.get('safe', "false") == 'true'

    access = user['access_control']
    last_modified = STORAGE.get_signature_last_modified()

    query_hash = sha256(f'{query}.{access}.{last_modified}'.encode('utf-8')).hexdigest()

    with forge.get_cachestore('al_ui.signature') as signature_cache:
        response = _get_cached_signatures(signature_cache, query_hash)
        if response:
            return response

        with Lock(f"{query_hash}.yar", 30):
            response = _get_cached_signatures(signature_cache, query_hash)
            if response:
                return response

            keys = [k['id']
                    for k in STORAGE.signature.search(query, fl="id", access_control=access, as_obj=False)['items']]
            signature_list = STORAGE.signature.multiget(keys, as_dictionary=False, as_obj=False)

            # Sort rules to satisfy dependencies
            duplicate_rules = []
            error_rules = []
            global_rules = []
            private_rules_no_dep = []
            private_rules_dep = []
            rules_no_dep = []
            rules_dep = []

            if safe:
                rules_map = {}
                for s in signature_list:
                    name = s.get('name', None)
                    if not name:
                        continue

                    version = int(s.get('meta', {}).get('rule_version', '1'))

                    p = rules_map.get(name, {})
                    pversion = int(p.get('meta', {}).get('rule_version', '0'))

                    if version < pversion:
                        duplicate_rules.append(name)
                        continue

                    rules_map[name] = s
                signature_list = rules_map.values()

            name_map = {}
            for s in signature_list:
                if s['type'].startswith("global"):
                    global_rules.append(s)
                    name_map[s['name']] = True
                elif s['type'].startswith("private"):
                    if s['depends'] is None or len(s['depends']) == 0:
                        private_rules_no_dep.append(s)
                        name_map[s['name']] = True
                    else:
                        private_rules_dep.append(s)
                else:
                    if s['depends'] is None or len(s['depends']) == 0:
                        rules_no_dep.append(s)
                        name_map[s['name']] = True
                    else:
                        rules_dep.append(s)

            global_rules = sorted(global_rules, key=lambda k: k['meta']['rule_id'])
            private_rules_no_dep = sorted(private_rules_no_dep, key=lambda k: k['meta']['rule_id'])
            rules_no_dep = sorted(rules_no_dep, key=lambda k: k['meta']['rule_id'])
            private_rules_dep = sorted(private_rules_dep, key=lambda k: k['meta']['rule_id'])
            rules_dep = sorted(rules_dep, key=lambda k: k['meta']['rule_id'])

            signature_list = global_rules + private_rules_no_dep
            while private_rules_dep:
                new_private_rules_dep = []
                for r in private_rules_dep:
                    found = False
                    for d in r['depends']:
                        if not name_map.get(d, False):
                            new_private_rules_dep.append(r)
                            found = True
                            break
                    if not found:
                        name_map[r['name']] = True
                        signature_list.append(r)

                if private_rules_dep == new_private_rules_dep:
                    for x in private_rules_dep:
                        error_rules += [d for d in x["depends"]]

                    if not safe:
                        for s in private_rules_dep:
                            name_map[s['name']] = True
                        signature_list += private_rules_dep

                    new_private_rules_dep = []

                private_rules_dep = new_private_rules_dep

            signature_list += rules_no_dep
            while rules_dep:
                new_rules_dep = []
                for r in rules_dep:
                    found = False
                    for d in r['depends']:
                        if not name_map.get(d, False):
                            new_rules_dep.append(r)
                            found = True
                            break
                    if not found:
                        name_map[r['name']] = True
                        signature_list.append(r)

                if rules_dep == new_rules_dep:
                    error_rules += [x["name"] for x in rules_dep]
                    if not safe:
                        for s in rules_dep:
                            name_map[s['name']] = True
                        signature_list += rules_dep

                    new_rules_dep = []

                rules_dep = new_rules_dep
            # End of sort

            error = ""
            if duplicate_rules:
                if safe:
                    err_txt = "were skipped"
                else:
                    err_txt = "exist"
                error += dedent("""\
                
                    // [ERROR] Duplicates rules {msg}:
                    //
                    //	{rules}
                    //
                    """).format(msg=err_txt, rules="\n//\t".join(duplicate_rules))
            if error_rules:
                if safe:
                    err_txt = "were skipped due to"
                else:
                    err_txt = "are"
                error += dedent("""\
                
                    // [ERROR] Some rules {msg} missing dependencies:
                    //
                    //	{rules}
                    //
                    """).format(msg=err_txt, rules="\n//\t".join(error_rules))
            # noinspection PyAugmentAssignment

            header = dedent("""\
                // Signatures last updated: {last_modified}
                // Yara file unique identifier: {query_hash}
                // Query executed to find signatures:
                //
                //	{query}
                // {error}
                // Number of rules in file:
                //
                """).format(query=query, error=error, last_modified=last_modified, query_hash=query_hash)

            rule_file_bin = header + YaraParser().dump_rule_file(signature_list)
            rule_file_bin = rule_file_bin

            signature_cache.save(query_hash, rule_file_bin.encode(encoding="UTF-8"), ttl=DEFAULT_CACHE_TTL)

            return make_file_response(
                rule_file_bin, f"al_yara_signatures_{query_hash[:7]}.yar",
                len(rule_file_bin), content_type="text/yara"
            )


@signature_api.route("/<sid>/<rev>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_signature(sid, rev, **kwargs):
    """
    Get the detail of a signature based of its ID and revision
    
    Variables:
    sid    =>     Signature ID
    rev    =>     Signature revision number
    
    Arguments: 
    None
    
    Data Block:
    None
     
    Result example:
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    """
    user = kwargs['user']
    data = STORAGE.signature.get(f"{sid}r.{rev}", as_obj=False)

    if data:
        if not Classification.is_accessible(user['classification'],
                                            data['meta'].get('classification',
                                                             Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to view this signature.", 403)

        # Cleanup
        for key in VALID_GROUPS:
            if data['meta'].get(key, None) is None:
                data['meta'].pop(key, None)

        if not Classification.enforce:
            data.pop('classification', None)

        return make_api_response(data)
    else:
        return make_api_response("", "Signature not found. (%s r.%s)" % (sid, rev), 404)


@signature_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def list_signatures(**kwargs):
    """
    List all the signatures in the system. 
    
    Variables:
    None 
    
    Arguments: 
    offset       => Offset at which we start giving signatures
    rows         => Numbers of signatures to return
    query        => Filter to apply on the signature list
    
    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total signatures found
     "offset": 0,                 # Offset in the signature list
     "rows": 100,                # Number of signatures returned
     "items": [{                  # List of Signatures:
       "name": "sig_name",          # Signature name    
       "tags": ["PECheck"],         # Signature tags
       "comments": [""],            # Signature comments lines
       "meta": {                    # Meta fields ( **kwargs )
         "id": "SID",                 # Mandatory ID field
         "rule_version": 1 },         # Mandatory Revision field
       "type": "rule",              # Rule type (rule, private rule ...)
       "strings": ['$ = "a"'],      # Rule string section (LIST)
       "condition": ["1 of them"]   # Rule condition section (LIST)
       }, ... ]}
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"

    try:
        return make_api_response(STORAGE.signature.search(query, offset=offset, rows=rows,
                                                          access_control=user['access_control'], as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@signature_api.route("/<sid>/<rev>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def set_signature(sid, rev, **kwargs):
    """
    [INCOMPLETE]
       - CHECK IF SIGNATURE NAME ALREADY EXISTS
    Update a signature defined by a sid and a rev.
       NOTE: The API will compare the old signature
             with the new one and will make the decision
             to increment the revision number or not. 
    
    Variables:
    sid    =>     Signature ID
    rev    =>     Signature revision number
    
    Arguments: 
    None
    
    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",          # Signature name    
     "tags": ["PECheck"],         # Signature tags
     "comments": [""],            # Signature comments lines
     "meta": {                    # Meta fields ( **kwargs )
       "id": "SID",                 # Mandatory ID field
       "rule_version": 1 },         # Mandatory Revision field
     "type": "rule",              # Rule type (rule, private rule ...)
     "strings": ['$ = "a"'],      # Rule string section (LIST)
     "condition": ["1 of them"]}  # Rule condition section (LIST)    
    
    Result example:
    {"success": true,      #If saving the rule was a success or not
     "sid": "0000000000",  #SID that the rule was assigned (Same as provided)
     "rev": 2 }            #Revision number at which the rule was saved.
    """
    user = kwargs['user']
    key = f"{sid}r.{rev}"

    # Get old signature
    old_data = STORAGE.signature.get(key, as_obj=False)
    if old_data:
        data = request.json
        # Test classification access
        if not Classification.is_accessible(user['classification'],
                                            data['meta'].get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed to change a signature to an "
                                         "higher classification than yours", 403)
    
        if not Classification.is_accessible(user['classification'],
                                            old_data['meta'].get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed to change a signature with "
                                         "higher classification than yours", 403)

        # Test signature type access
        if not user['is_admin'] and "global" in data['type']:
            return make_api_response("", "Only admins are allowed to add global signatures.", 403)

        # Check signature statuses
        if old_data['meta']['al_status'] != data['meta']['al_status']:
            return make_api_response({"success": False}, "You cannot change the signature "
                                                         "status through this API.", 400)

        # Check if rule requires a revision bump
        if YaraParser.require_bump(data, old_data):
            # Get new ID
            data['meta']['rule_id'] = sid
            data['meta']['rule_version'] = STORAGE.get_signature_last_revision_for_id(sid) + 1

            # Cleanup fields
            if 'creation_date' in data['meta']:
                del(data['meta']['creation_date'])
            if "meta_extra" in data:
                if 'al_state_change_date' in data['meta_extra']:
                    del(data['meta_extra']['al_state_change_date'])
                if 'al_state_change_user' in data['meta_extra']:
                    del(data['meta_extra']['al_state_change_user'])

            data['meta']['al_status'] = "TESTING"
            key = f"{sid}r.{data['meta']['rule_version']}"
        else:

            # Make sure rule id and revision match
            data['meta']['rule_id'] = sid
            data['meta']['rule_version'] = rev

        # Reset signature last modified
        if 'last_modified' in data['meta']:
            del (data['meta']['last_modified'])

        # Set last saved by
        if "meta_extra" not in data:
            data['meta_extra'] = {'last_saved_by': user['uname']}
        else:
            data['meta_extra']['last_saved_by'] = user['uname']

        # check rule dependencies
        yara_modules = YaraParser.YARA_MODULES.get(data['meta'].get('yara_version', None), None)
        data['depends'], data['modules'] = YaraParser.parse_dependencies(data['condition'], yara_modules)

        # Validate rule
        res = YaraParser.validate_rule(data)
        if res['valid']:
            # Save signature
            data['warning'] = res.get('warning', None)
            return make_api_response({"success": STORAGE.signature.save(key, data),
                                      "sid": data['meta']['rule_id'],
                                      "rev": int(data['meta']['rule_version'])})
        else:
            return make_api_response({"success": False}, res, 403)
    else:
        return make_api_response({"success": False}, "Signature not found. %s" % key, 404)


@signature_api.route("/stats/", methods=["GET"])
@api_login(allow_readonly=False)
def signature_statistics(**kwargs):
    """
    Gather all signatures stats in system

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [                             # List of signature stats
      {"sid": "ORG_000000",          # Signature ID
       "rev": 1,                     # Signature version
       "classification": "U",        # Classification of the signature
       "name": "Signature Name"      # Signature name
       "count": "100",               # Count of times signatures seen
       "min": 0,                     # Lowest score found
       "avg": 172,                   # Average of all scores
       "max": 780,                   # Highest score found
      },
     ...
    ]"""

    user = kwargs['user']

    def get_stat_for_signature(p_sid, p_rev, p_name, p_classification):
        stats = STORAGE.result.stats("result.score",
                                     query=f"result.tags.value:{p_name} AND result.tags.type:FILE_YARA_RULE")
        if stats['count'] == 0:
            return {
                'sid': p_sid,
                'rev': int(p_rev),
                'name': p_name,
                'classification': p_classification,
                'count': stats['count'],
                'min': 0,
                'max': 0,
                'avg': 0,
            }
        else:
            return {
                'sid': p_sid,
                'rev': int(p_rev),
                'name': p_name,
                'classification': p_classification,
                'count': stats['count'],
                'min': int(stats['min']),
                'max': int(stats['max']),
                'avg': int(stats['avg']),
            }

    sig_list = sorted([(x['meta']['rule_id'], x['meta']['rule_version'], x['name'], x['classification'])
                       for x in STORAGE.signature.stream_search("name:*",
                                                                fl="name,meta.rule_id,meta.rule_version,classification",
                                                                access_control=user['access_control'], as_obj=False)])

    with concurrent.futures.ThreadPoolExecutor(max(min(len(sig_list), 20), 1)) as executor:
        res = [executor.submit(get_stat_for_signature, sid, rev, name, classification)
               for sid, rev, name, classification in sig_list]

    return make_api_response(sorted([r.result() for r in res], key=lambda i: (i['sid'], i['rev'])))


@signature_api.route("/update_available/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def update_available(**_):
    """
    Check if updated signatures are.

    Variables:
    None

    Arguments:
    last_update        => ISO time of last update.

    Data Block:
    None

    Result example:
    { "update_available" : true }      # If updated rules are available.
    """
    last_update = iso_to_epoch(request.args.get('last_update', '1970-01-01T00:00:00.000000Z'))
    last_modified = iso_to_epoch(STORAGE.get_signature_last_modified())

    return make_api_response({"update_available": last_modified > last_update})
