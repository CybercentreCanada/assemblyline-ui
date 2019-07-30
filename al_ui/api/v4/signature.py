import concurrent.futures

from flask import request
from hashlib import sha256
from textwrap import dedent

from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch, now_as_iso
from assemblyline.common.uid import get_id_from_data, SHORT
from assemblyline.odm.models.signature import DEPLOYED_STATUSES, STALE_STATUSES, DRAFT_STATUSES
from assemblyline.remote.datatypes.lock import Lock
from al_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from al_ui.config import LOGGER, STORAGE
Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'signature'
signature_api = make_subapi_blueprint(SUB_API, api_version=4)
signature_api._doc = "Perform operations on signatures"

DEFAULT_CACHE_TTL = 24 * 60 * 60  # 1 Day


@signature_api.route("/add/", methods=["PUT"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False, require_type=['signature_importer'])
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
    {"name": "sig_name",           # Signature name
     "type": "yara",               # One of yara, suricata or tagcheck
     "data": "rule sample {...}",  # Data of the rule to be added
     "source": "yara_signatures"   # Source from where the signature has been gathered
    }

    Result example:
    {"success": true,            #If saving the rule was a success or not
     "id": "<TYPE>_<SID>_<REVISION>"}  #ID that was assigned to the signature
    """
    data = request.json

    if data.get('type', None) is None or data['name'] is None or data['data'] is None:
        return make_api_response("", f"Signature name, type and data are mandatory fields.", 400)

    # Compute signature ID if missing
    data['signature_id'] = data.get('signature_id', get_id_from_data(data['data'], SHORT))
    key = f"{data['type']}_{data['signature_id']}_{data['revision']}"

    # Test signature name
    check_name_query = f"name:{data['name']} " \
                       f"AND type:{data['type']} " \
                       f"AND source:{data['source']} " \
                       f"AND NOT id:{data['siganture_id']}*"
    other = STORAGE.signature.search(check_name_query, fl='id', rows='0')
    if other['total'] > 0:
        return make_api_response(
            {"success": False},
            "A signature with that name already exists",
            400
        )

    # Save the signature
    return make_api_response({"success": STORAGE.signature.save(key, data),
                              "id": key})


# noinspection PyPep8Naming
@signature_api.route("/change_status/<sid>/<status>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False, require_type=['admin', 'signature_manager'])
def change_status(sid, status, **kwargs):
    """
    Change the status of a signature
       
    Variables:
    sid    =>  ID of the signature
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

    data = STORAGE.signature.get(sid, as_obj=False)
    if data:
        if not Classification.is_accessible(user['classification'],
                                            data.get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        if data['status'] in STALE_STATUSES and status not in DRAFT_STATUSES:
            return make_api_response("",
                                     f"Only action available while signature in {data['status']} "
                                     f"status is to change signature to a DRAFT status. ({', '.join(DRAFT_STATUSES)})",
                                     403)

        if data['status'] in DEPLOYED_STATUSES and status in DRAFT_STATUSES:
            return make_api_response("",
                                     f"You cannot change the status of signature {sid} from "
                                     f"{data['status']} to {status}.", 403)

        query = f"status:{status} AND signature_id:{data['signature_id']} AND NOT id:{sid}"
        today = now_as_iso()
        uname = user['uname']

        if status not in ['DISABLED', 'INVALID', 'TESTING']:
            keys = [k['id']
                    for k in STORAGE.signature.search(query, fl="id", as_obj=False)['items']]
            for other in STORAGE.signature.multiget(keys, as_obj=False, as_dictionary=False):
                other['state_change_date'] = today
                other['state_change_user'] = uname
                other['status'] = 'DISABLED'

                STORAGE.signature.save(f"{other['meta']['rule_id']}r.{other['meta']['rule_version']}", other)

        data['state_change_date'] = today
        data['state_change_user'] = uname
        data['status'] = status

        return make_api_response({"success": STORAGE.signature.save(sid, data)})
    else:
        return make_api_response("", f"Signature not found. ({sid})", 404)


@signature_api.route("/<sid>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False, require_type=['admin', 'signature_manager'])
def delete_signature(sid, **kwargs):
    """
    Delete a signature based of its ID

    Variables:
    sid    =>     Signature ID

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}  # Signature delete successful
    """
    user = kwargs['user']
    data = STORAGE.signature.get(sid, as_obj=False)
    if data:
        if not Classification.is_accessible(user['classification'],
                                            data.get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to delete this signature.", 403)
        return make_api_response({"success": STORAGE.signature.delete(sid)})
    else:
        return make_api_response("", f"Signature not found. ({sid})", 404)


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
    # TODO: Fix for new signature stuff
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

            rule_file_bin = header # + YaraParser().dump_rule_file(signature_list)
            rule_file_bin = rule_file_bin

            signature_cache.save(query_hash, rule_file_bin.encode(encoding="UTF-8"), ttl=DEFAULT_CACHE_TTL)

            return make_file_response(
                rule_file_bin, f"al_yara_signatures_{query_hash[:7]}.yar",
                len(rule_file_bin), content_type="text/yara"
            )


@signature_api.route("/<sid>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_signature(sid, **kwargs):
    """
    Get the detail of a signature based of its ID and revision
    
    Variables:
    sid    =>     Signature ID
    
    Arguments: 
    None
    
    Data Block:
    None
     
    Result example:
    {}
    """
    user = kwargs['user']
    data = STORAGE.signature.get(sid, as_obj=False)

    if data:
        if not Classification.is_accessible(user['classification'],
                                            data.get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to view this signature.", 403)

        return make_api_response(data)
    else:
        return make_api_response("", f"Signature not found. ({sid})", 404)


@signature_api.route("/<sid>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False, require_type=['signature_importer'])
def set_signature(sid, **_):
    """
    Update a signature defined by a sid and a rev.
       NOTE: The API will compare the old signature
             with the new one and will make the decision
             to increment the revision number or not. 
    
    Variables:
    sid    =>     Signature ID

    Arguments: 
    None
    
    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",           # Signature name
     "type": "yara",               # One of yara, suricata or tagcheck
     "data": "rule sample {...}",  # Data of the rule to be added
     "source": "yara_signatures"   # Source from where the signature has been gathered
    }

    Result example:
    {"success": true,      #If saving the rule was a success or not
     "id": "<TYPE>_<SID>_<REVISION>"}  #ID that was assigned to the signature
    """
    # Get old signature
    old_data = STORAGE.signature.get(sid, as_obj=False)
    if old_data:
        data = request.json
        return make_api_response({"success": STORAGE.signature.save(sid, data),
                                  "sid": sid})
    else:
        return make_api_response({"success": False}, "Signature not found. %s" % sid, 404)


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
    # TODO: Fix for new signature stuff

    user = kwargs['user']

    def get_stat_for_signature(p_sid, p_rev, p_name, p_type, p_classification):
        stats = STORAGE.result.stats("result.score",
                                     query=f'result.sections.tags.file.rule.{type}:"{p_name}"')
        if stats['count'] == 0:
            return {
                'sid': p_sid,
                'rev': int(p_rev),
                'name': p_name,
                'type': p_type,
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
                'type': p_type,
                'classification': p_classification,
                'count': stats['count'],
                'min': int(stats['min']),
                'max': int(stats['max']),
                'avg': int(stats['avg']),
            }

    sig_list = sorted([(x['signature_id'], x['revision'], x['name'], x['type'], x['classification'])
                       for x in STORAGE.signature.stream_search("name:*",
                                                                fl="name,type,signature_id,revision,classification",
                                                                access_control=user['access_control'], as_obj=False)])

    with concurrent.futures.ThreadPoolExecutor(max(min(len(sig_list), 20), 1)) as executor:
        res = [executor.submit(get_stat_for_signature, sid, rev, name, sig_type, classification)
               for sid, rev, name, sig_type, classification in sig_list]

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
    type               => Signature type to check

    Data Block:
    None

    Result example:
    { "update_available" : true }      # If updated rules are available.
    """
    sig_type = request.args.get('type', '*')
    last_update = iso_to_epoch(request.args.get('last_update', '1970-01-01T00:00:00.000000Z'))
    last_modified = iso_to_epoch(STORAGE.get_signature_last_modified(sig_type))

    return make_api_response({"update_available": last_modified > last_update})
