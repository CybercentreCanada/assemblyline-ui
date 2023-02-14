import re

from flask import request
from hashlib import sha256

from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch, now_as_iso
from assemblyline.common.memory_zip import InMemoryZip
from assemblyline.odm.messages.changes import Operation
from assemblyline.odm.models.signature import DEPLOYED_STATUSES, STALE_STATUSES, DRAFT_STATUSES
from assemblyline.odm.models.service import SIGNATURE_DELIMITERS
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.lock import Lock
from assemblyline.remote.datatypes.events import EventSender
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.config import LOGGER, SERVICE_LIST, STORAGE, config, CLASSIFICATION as Classification
from assemblyline_ui.helper.signature import append_source_status

SUB_API = 'signature'
signature_api = make_subapi_blueprint(SUB_API, api_version=4)
signature_api._doc = "Perform operations on signatures"

DEFAULT_CACHE_TTL = 24 * 60 * 60  # 1 Day

signature_event_sender = EventSender('changes.signatures',
                                     host=config.core.redis.nonpersistent.host,
                                     port=config.core.redis.nonpersistent.port)
service_event_sender = EventSender('changes.services',
                                   host=config.core.redis.nonpersistent.host,
                                   port=config.core.redis.nonpersistent.port)


def _get_signature_delimiters():
    signature_delimiters = {}
    for service in SERVICE_LIST:
        if service.get("update_config", {}).get("generates_signatures", False):
            signature_delimiters[service['name'].lower()] = _get_signature_delimiter(service['update_config'])
    return signature_delimiters


def _get_signature_delimiter(update_config):
    delimiter_type = update_config['signature_delimiter']
    if delimiter_type == 'custom':
        delimiter = update_config['custom_delimiter'].encode().decode('unicode-escape')
    else:
        delimiter = SIGNATURE_DELIMITERS.get(delimiter_type, '\n\n')
    return {'type': delimiter_type, 'delimiter': delimiter}


DEFAULT_DELIMITER = "\n\n"
DELIMITERS = forge.CachedObject(_get_signature_delimiters)


@signature_api.route("/add_update/", methods=["POST", "PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_import])
def add_update_signature(**_):
    """
    Add or Update the signature based on the signature ID, type and source.

    Variables:
    None

    Arguments:
    dedup_name      ->      Should the signature manager check if the signature name already exists
                            Default: true

    Data Block (REQUIRED): # Signature block
    {"name": "sig_name",           # Signature name
     "type": "yara",               # One of yara, suricata or tagcheck
     "data": "rule sample {...}",  # Data of the rule to be added
     "source": "yara_signatures"   # Source from where the signature has been gathered
    }

    Result example:
    {"success": true,      #If saving the rule was a success or not
     "id": "<TYPE>_<SOURCE>_<ID>"}  #ID that was assigned to the signature
    """
    data = request.json
    dedup_name = request.args.get('dedup_name', 'true').lower() == 'true'

    if data.get('type', None) is None or data['name'] is None or data['data'] is None:
        return make_api_response("", "Signature id, name, type and data are mandatory fields.", 400)

    # Compute signature ID if missing
    data['signature_id'] = data.get('signature_id', data['name'])

    key = f"{data['type']}_{data['source']}_{data['signature_id']}"

    # Test signature name
    if dedup_name:
        check_name_query = f"name:\"{data['name']}\" " \
                           f"AND type:\"{data['type']}\" " \
                           f"AND source:\"{data['source']}\" " \
                           f"AND NOT id:\"{key}\""
        other = STORAGE.signature.search(check_name_query, fl='id', rows='0')
        if other['total'] > 0:
            return make_api_response(
                {"success": False},
                "A signature with that name already exists",
                400
            )

    old = STORAGE.signature.get(key, as_obj=False)
    if old:
        if old['data'] == data['data']:
            return make_api_response({"success": True, "id": key})

        # If rule has been deprecated/disabled after initial deployment, then disable it
        if not (data['status'] != old['status'] and data['status'] == "DISABLED"):
            data['status'] = old['status']

        # Preserve last state change
        data['state_change_date'] = old['state_change_date']
        data['state_change_user'] = old['state_change_user']

        # Preserve signature stats
        data['stats'] = old['stats']

    # Save the signature
    success = STORAGE.signature.save(key, data)
    if success:
        signature_event_sender.send(data['type'], {
            'signature_id': data['signature_id'],
            'signature_type': data['type'],
            'source': data['source'],
            'operation': Operation.Modified if old else Operation.Added
        })

    return make_api_response({"success": success, "id": key})


@signature_api.route("/add_update_many/", methods=["POST", "PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_import])
def add_update_many_signature(**_):
    """
    Add or Update a list of the signatures based on their signature ID, type and source.

    Variables:
    None

    Arguments:
    dedup_name      ->      Should the signature manager check if the signature name already exists
                            Default: true

    Data Block (REQUIRED):
    [                             # List of Signature blocks
     {"name": "sig_name",           # Signature name
      "type": "yara",               # One of yara, suricata or tagcheck
      "data": "rule sample {...}",  # Data of the rule to be added
      "source": "yara_signatures"   # Source from where the signature has been gathered
     },
     ...
    ]

    Result example:
    {"success": 23,                # Number of rules that succeeded
     "errors": [],                 # List of rules that failed
     "skipped": [],                # List of skipped signatures, they already exist
    """
    data = request.json
    dedup_name = request.args.get('dedup_name', 'true').lower() == 'true'
    source = request.args.get('source', None)
    sig_type = request.args.get('sig_type', None)

    if source is None or sig_type is None or not isinstance(data, list):
        return make_api_response("", "Source, source type and data are mandatory fields.", 400)

    # Test signature names
    names_map = {x['name']: f"{x['type']}_{x['source']}_{x.get('signature_id', x['name'])}" for x in data}

    skip_list = []
    if dedup_name:
        for item in STORAGE.signature.stream_search(f"type: \"{sig_type}\" AND source:\"{source}\"",
                                                    fl="id,name", as_obj=False):
            lookup_id = names_map.get(item['name'], None)
            if lookup_id and lookup_id != item['id']:
                skip_list.append(lookup_id)

        if skip_list:
            data = [x for x in data if f"{x['type']}_{x['source']}_{x.get('signature_id', x['name'])}" not in skip_list]

    old_data = STORAGE.signature.multiget(list(names_map.values()), as_dictionary=True, as_obj=False,
                                          error_on_missing=False)

    plan = STORAGE.signature.get_bulk_plan()
    for rule in data:
        key = f"{rule['type']}_{rule['source']}_{rule.get('signature_id', rule['name'])}"
        if key in old_data:
            # If rule has been deprecated/disabled after initial deployment, then disable it
            if not (rule['status'] != old_data[key]['status'] and rule['status'] == "DISABLED"):
                rule['status'] = old_data[key]['status']

            # Preserve last state change
            rule['state_change_date'] = old_data[key]['state_change_date']
            rule['state_change_user'] = old_data[key]['state_change_user']

            # Preserve signature stats
            rule['stats'] = old_data[key]['stats']

        plan.add_upsert_operation(key, rule)

    if not plan.empty:
        res = STORAGE.signature.bulk(plan)

        signature_event_sender.send(sig_type, {
            'signature_id': '*',
            'signature_type': sig_type,
            'source': source,
            'operation': Operation.Modified
        })

        return make_api_response({"success": len(res['items']), "errors": res['errors'], "skipped": skip_list})

    return make_api_response({"success": 0, "errors": [], "skipped": skip_list})


@signature_api.route("/sources/<service>/", methods=["PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_manage])
def add_signature_source(service, **_):
    """
    Add a signature source for a given service

    Variables:
    service           =>      Service to which we want to add the source to

    Arguments:
    None

    Data Block:
    {
      "uri": "http://somesite/file_to_get",   # URI to fetch for parsing the rules
      "name": "signature_file.yar",           # Name of the file we will parse the rules as
      "username": null,                       # Username used to get to the URI
      "password": null,                       # Password used to get to the URI
      "header": {                             # Header sent during the request to the URI
        "X_TOKEN": "SOME RANDOM TOKEN"          # Exemple of header
      },
      "private_key": null,                    # Private key used to get to the URI
      "pattern": "^*.yar$"                    # Regex pattern use to get appropriate files from the URI
    }

    Result example:
    {"success": True/False}   # if the operation succeeded of not
    """
    try:
        data = request.json
    except (ValueError, KeyError):
        return make_api_response({"success": False},
                                 err="Invalid source object data",
                                 status_code=400)

    # Ensure data source doesn't have spaces in name
    data['name'] = re.sub('[^0-9a-zA-Z_]+', '', data['name'].replace(" ", "_"))

    # Ensure private_key (if any) ends with a \n
    if data.get('private_key', None) and not data['private_key'].endswith("\n"):
        data['private_key'] += "\n"

    service_data = STORAGE.get_service_with_delta(service, as_obj=False)
    if not service_data.get('update_config', {}):
        return make_api_response({"success": False},
                                 err="This service is not configured to use external sources.",
                                 status_code=400)

    current_sources = service_data.get('update_config', {}).get('sources', [])
    for source in current_sources:
        if source['name'] == data['name']:
            return make_api_response({"success": False},
                                     err=f"Update source name already exist: {data['name']}",
                                     status_code=400)

    current_sources.append(data)
    service_delta = STORAGE.service_delta.get(service, as_obj=False)
    if service_delta.get('update_config') is None:
        service_delta['update_config'] = {"sources": current_sources}
    else:
        service_delta['update_config']['sources'] = current_sources

    # Save the signature
    success = STORAGE.service_delta.save(service, service_delta)
    if success:
        service_event_sender.send(service, {
            'operation': Operation.Modified,
            'name': service
        })
    return make_api_response({"success": success})


# noinspection PyPep8Naming
@signature_api.route("/change_status/<signature_id>/<status>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.signature_manage])
def change_status(signature_id, status, **kwargs):
    """
    Change the status of a signature

    Variables:
    signature_id    =>  ID of the signature
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

    data = STORAGE.signature.get(signature_id, as_obj=False)
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
                                     f"You cannot change the status of signature {signature_id} from "
                                     f"{data['status']} to {status}.", 403)

        today = now_as_iso()
        uname = user['uname']

        if status not in ['DISABLED', 'INVALID', 'TESTING']:
            query = f"status:{status} AND signature_id:{data['signature_id']} AND NOT id:{signature_id}"
            others_operations = [
                ('SET', 'last_modified', today),
                ('SET', 'state_change_date', today),
                ('SET', 'state_change_user', uname),
                ('SET', 'status', 'DISABLED')
            ]
            STORAGE.signature.update_by_query(query, others_operations)

        operations = [
            ('SET', 'last_modified', today),
            ('SET', 'state_change_date', today),
            ('SET', 'state_change_user', uname),
            ('SET', 'status', status)
        ]

        success = STORAGE.signature.update(signature_id, operations)
        signature_event_sender.send(data['type'], {
            'signature_id': signature_id,
            'signature_type': data['type'],
            'source': data['source'],
            'operation': Operation.Modified
        })
        return make_api_response({"success": success})
    else:
        return make_api_response("", f"Signature not found. ({signature_id})", 404)


@signature_api.route("/<signature_id>/", methods=["DELETE"])
@api_login(allow_readonly=False, require_role=[ROLES.signature_manage])
def delete_signature(signature_id, **kwargs):
    """
    Delete a signature based of its ID

    Variables:
    signature_id    =>     Signature ID

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": True}  # Signature delete successful
    """
    user = kwargs['user']
    data = STORAGE.signature.get(signature_id, as_obj=False)
    if data:
        if not Classification.is_accessible(user['classification'],
                                            data.get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to delete this signature.", 403)

        ret_val = STORAGE.signature.delete(signature_id)

        signature_event_sender.send(data['type'], {
            'signature_id': signature_id,
            'signature_type': data['type'],
            'source': data['source'],
            'operation': Operation.Removed
        })
        return make_api_response({"success": ret_val})
    else:
        return make_api_response("", f"Signature not found. ({signature_id})", 404)


@signature_api.route("/sources/<service>/<path:name>/", methods=["DELETE"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_manage])
def delete_signature_source(service, name, **_):
    """
    Delete a signature source by name for a given service

    Variables:
    service           =>      Service to which we want to delete the source from
    name              =>      Name of the source you want to remove

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "source": True,       # if deleting the source succeeded or not
     "signatures": False   # if deleting associated signatures deleted or not

    }
    """
    service_data = STORAGE.get_service_with_delta(service, as_obj=False)
    current_sources = service_data.get('update_config', {}).get('sources', [])

    if not service_data.get('update_config', {}):
        return make_api_response({"success": False},
                                 err="This service is not configured to use external sources. "
                                     "Therefore you cannot delete one of its sources.",
                                 status_code=400)

    new_sources = []
    found = False
    for source in current_sources:
        if name == source['name']:
            found = True
        else:
            new_sources.append(source)

    if not found:
        return make_api_response({"success": False},
                                 err=f"Could not found source '{name}' in service {service}.",
                                 status_code=404)

    service_delta = STORAGE.service_delta.get(service, as_obj=False)
    if service_delta.get('update_config') is None:
        service_delta['update_config'] = {"sources": new_sources}
    else:
        service_delta['update_config']['sources'] = new_sources

    # Save the new sources
    success = STORAGE.service_delta.save(service, service_delta)
    if success:
        # Remove old source signatures and clear related caching entries from Redis
        STORAGE.signature.delete_by_query(f'type:"{service.lower()}" AND source:"{name}"')
        service_updates = Hash(f'service-updates-{service}', config.core.redis.persistent.host,
                               config.core.redis.persistent.port)
        [service_updates.delete(k) for k in service_updates.keys() if k.startswith(f'{name}.')]


    service_event_sender.send(service, {
        'operation': Operation.Modified,
        'name': service
    })
    return make_api_response({"success": success})


# noinspection PyBroadException
def _get_cached_signatures(signature_cache, query_hash):
    try:
        s = signature_cache.get(query_hash)
        if s is None or s == b'':
            return s
        return make_file_response(
            s, f"al_signatures_{query_hash[:7]}.zip", len(s), content_type="application/zip"
        )
    except Exception:  # pylint: disable=W0702
        LOGGER.exception('Failed to read cached signatures:')

    return None


@signature_api.route("/download/", methods=["GET"])
@api_login(check_xsrf_token=False, allow_readonly=False,
           require_role=[ROLES.signature_download])
def download_signatures(**kwargs):
    """
    Download signatures from the system.

    Variables:
    None

    Arguments:
    query       => Query used to filter the signatures
                   Default: All deployed signatures

    Data Block:
    None

    Result example:
    <A zip file containing all signatures files from the different sources>
    """
    user = kwargs['user']
    query = request.args.get('query', 'status:DEPLOYED')

    access = user['access_control']
    last_modified = STORAGE.get_signature_last_modified()

    query_hash = sha256(f'{query}.{access}.{last_modified}'.encode('utf-8')).hexdigest()

    with forge.get_cachestore('signatures') as signature_cache:
        response = _get_cached_signatures(signature_cache, query_hash)
        if response:
            return response

        with Lock(f"al_signatures_{query_hash[:7]}.zip", 30):
            response = _get_cached_signatures(signature_cache, query_hash)
            if response:
                return response

            output_files = {}

            signature_list = sorted(
                STORAGE.signature.stream_search(
                    query, fl="signature_id,type,source,data,order", access_control=access, as_obj=False),
                key=lambda x: x['order'])

            for sig in signature_list:
                out_fname = f"{sig['type']}/{sig['source']}"
                if DELIMITERS.get(sig['type'], {}).get('type', None) == 'file':
                    out_fname = f"{out_fname}/{sig['signature_id']}"
                output_files.setdefault(out_fname, [])
                output_files[out_fname].append(sig['data'])

            output_zip = InMemoryZip()
            for fname, data in output_files.items():
                separator = DELIMITERS.get(fname.split('/')[0], {}).get('delimiter', DEFAULT_DELIMITER)
                output_zip.append(fname, separator.join(data))

            rule_file_bin = output_zip.read()

            signature_cache.save(query_hash, rule_file_bin, ttl=DEFAULT_CACHE_TTL)

            return make_file_response(
                rule_file_bin, f"al_signatures_{query_hash[:7]}.zip",
                len(rule_file_bin), content_type="application/zip"
            )


@signature_api.route("/<signature_id>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.signature_view])
def get_signature(signature_id, **kwargs):
    """
    Get the detail of a signature based of its ID and revision

    Variables:
    signature_id    =>     Signature ID

    Arguments:
    None

    Data Block:
    None

    Result example:
    {}
    """
    user = kwargs['user']
    data = STORAGE.signature.get(signature_id, as_obj=False)

    if data:
        if not Classification.is_accessible(user['classification'],
                                            data.get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to view this signature.", 403)

        # Always refresh stats when someone get a signature
        data.update({'stats': STORAGE.get_stat_for_signature(signature_id, data['source'], data['name'],
                                                             data['type'])})

        return make_api_response(data)
    else:
        return make_api_response("", f"Signature not found. ({signature_id})", 404)


@signature_api.route("/sources/", methods=["GET"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_manage])
def get_signature_sources(**_):
    """
    Get all signature sources

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     'Yara': {
        {
          "uri": "http://somesite/file_to_get",   # URI to fetch for parsing the rules
          "name": "signature_file.yar",           # Name of the file we will parse the rules as
          "username": null,                       # Username used to get to the URI
          "password": null,                       # Password used to get to the URI
          "header": {                             # Header sent during the request to the URI
            "X_TOKEN": "SOME RANDOM TOKEN"          # Exemple of header
          },
          "private_key": null,                    # Private key used to get to the URI
          "pattern": "^*.yar$"                    # Regex pattern use to get appropriate files from the URI
        }, ...
      }, ...
    }
    """
    services = STORAGE.list_all_services(full=True, as_obj=False)

    out = {}
    for service in [s for s in services if s.get("update_config", {})]:
        append_source_status(service)
        out[service['name']] = dict(sources=service['update_config']['sources'],
                                    generates_signatures=service['update_config']['generates_signatures'])

    # Save the signature
    return make_api_response(out)


@signature_api.route("/sources/update/<service>/", methods=["PUT"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_manage])
def trigger_signature_source_update(service, **_):
    """
    Manually trigger signature sources to update for a given service

    Variables:
    service           =>      Service to which we want to update the source

    Arguments:
    sources           =>      List of sources to trigger an update for.
                              Default: Update all sources

    Data Block:
    None

    Result example:
    {"success": True/False, "sources": ['SOURCE_A', 'SOURCE_B']}
    """

    service_delta = STORAGE.get_service_with_delta(service, as_obj=False)
    if not service_delta.get('update_config'):
        # Raise exception, service doesn't have an update configuration
        return make_api_response({"success": False},
                                 err="{service} doesn't contain an update configuration.",
                                 status_code=404)

    sources = request.args.get('sources', None)
    if not sources:
        # Update them all
        sources = [src['name'] for src in service_delta['update_config']['sources']]

    elif isinstance(sources, str):
        # Update a subset
        # Ensure the source list passed is actually valid to the service
        sources = [src['name']
                   for src in service_delta['update_config']['sources'] if src['name'] in sources.split(',')]

    source_event_sender = EventSender('changes.sources',
                                      host=config.core.redis.nonpersistent.host,
                                      port=config.core.redis.nonpersistent.port)

    # Set state to a queued state for all sources involved
    service_updates = Hash(f'service-updates-{service}', config.core.redis.persistent.host,
                           config.core.redis.persistent.port)
    [service_updates.set(
        key=f'{src}.status', value=dict(state='UPDATING', message='Queued for update..', ts=now_as_iso()))
     for src in sources]

    # Send event to service update to trigger a targetted source update
    source_event_sender.send(service.lower(), data=sources)

    return make_api_response({"success": True, "sources": sources})


@signature_api.route("/sources/<service>/<name>/", methods=["POST"])
@api_login(audit=False, allow_readonly=False, require_role=[ROLES.signature_manage])
def update_signature_source(service, name, **_):
    """
    Update a signature source by name for a given service

    Variables:
    service           =>      Service to which we want to update the source
    name              =>      Name of the source you want update

    Arguments:
    None

    Data Block:
    {
      "uri": "http://somesite/file_to_get",   # URI to fetch for parsing the rules
      "name": "signature_file.yar",           # Name of the file we will parse the rules as
      "username": null,                       # Username used to get to the URI
      "password": null,                       # Password used to get to the URI
      "header": {                             # Header sent during the request to the URI
        "X_TOKEN": "SOME RANDOM TOKEN"          # Exemple of header
      },
      "private_key": null,                    # Private key used to get to the URI
      "pattern": "^*.yar$"                    # Regex pattern use to get appropriate files from the URI
    }

    Result example:
    {"success": True/False}   # if the operation succeeded of not
    """
    data = request.json
    service_data = STORAGE.get_service_with_delta(service, as_obj=False)
    current_sources = service_data.get('update_config', {}).get('sources', [])

    # Ensure private_key (if any) ends with a \n
    if data.get('private_key', None) and not data['private_key'].endswith("\n"):
        data['private_key'] += "\n"

    if name != data['name']:
        return make_api_response({"success": False},
                                 err="You are not allowed to change the source name.",
                                 status_code=400)

    if not service_data.get('update_config', {}):
        return make_api_response({"success": False},
                                 err="This service is not configured to use external sources. "
                                 "Therefore you cannot update its sources.",
                                 status_code=400)

    if len(current_sources) == 0:
        return make_api_response({"success": False},
                                 err="This service does not have any sources therefore you cannot update any source.",
                                 status_code=400)

    new_sources = []
    found = False
    classification_changed = False
    for source in current_sources:
        if data['name'] == source['name']:
            new_sources.append(data)
            found = True
            classification_changed = data['default_classification'] != source['default_classification']
        else:
            new_sources.append(source)

    if not found:
        return make_api_response({"success": False},
                                 err=f"Could not found source '{data.name}' in service {service}.",
                                 status_code=404)

    service_delta = STORAGE.service_delta.get(service, as_obj=False)
    if service_delta.get('update_config') is None:
        service_delta['update_config'] = {"sources": new_sources}
    else:
        service_delta['update_config']['sources'] = new_sources

    # Has the classification changed?
    if classification_changed:
        class_norm = Classification.normalize_classification(data['default_classification'])
        STORAGE.signature.update_by_query(query=f'source:"{data["name"]}"',
                                          operations=[("SET", "classification", class_norm),
                                                      ("SET", "last_modified", now_as_iso())])

    # Save the signature
    success = STORAGE.service_delta.save(service, service_delta)
    if classification_changed:
        # Notify that signatures have changed (trigger local_update)
        signature_event_sender.send(service, {
            'signature_id': '*',
            'signature_type': service.lower(),
            'source': data['name'],
            'operation': Operation.Modified
        })
    else:
        # Notify that a source configuration has changes (trigger source_update)
        service_event_sender.send(service, {
            'operation': Operation.Modified,
            'name': service
        })
    return make_api_response({"success": success})


@signature_api.route("/stats/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.signature_view])
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
      {"id": "ORG_000000",           # Signature ID
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

    stats = []
    for sig in STORAGE.signature.stream_search("id:*", access_control=user['access_control'], fl='id,*', as_obj=False):
        stats.append({
            'avg': sig.get('stats', {}).get('avg', 0),
            'classification': sig['classification'],
            'count': sig.get('stats', {}).get('count', 0),
            'first_hit': sig.get('stats', {}).get('first_hit', None),
            'id': sig['id'],
            'last_hit': sig.get('stats', {}).get('last_hit', None),
            'max': sig.get('stats', {}).get('max', 0),
            'min': sig.get('stats', {}).get('min', 0),
            'name': sig['name'],
            'source': sig['source'],
            'sum': sig.get('stats', {}).get('sum', 0),
            'type': sig['type'],

        })

    return make_api_response(stats)


@signature_api.route("/update_available/", methods=["GET"])
@api_login(allow_readonly=False,
           require_role=[ROLES.signature_view])
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
