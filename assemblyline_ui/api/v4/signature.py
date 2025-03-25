import re
from hashlib import sha256

from assemblyline.common import forge
from assemblyline.common.isotime import now_as_iso
from assemblyline.datastore.exceptions import VersionConflictException
from assemblyline.odm.messages.changes import Operation
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.events import EventSender
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.lock import Lock
from assemblyline_core.signature_client import SignatureClient
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.config import LOGGER, STORAGE, config
from assemblyline_ui.helper.signature import append_source_status
from flask import request

SUB_API = 'signature'
signature_api = make_subapi_blueprint(SUB_API, api_version=4)
signature_api._doc = "Perform operations on signatures"

DEFAULT_CACHE_TTL = 24 * 60 * 60  # 1 Day
CLIENT = SignatureClient(STORAGE)


signature_event_sender = EventSender('changes.signatures',
                                     host=config.core.redis.nonpersistent.host,
                                     port=config.core.redis.nonpersistent.port)
service_event_sender = EventSender('changes.services',
                                   host=config.core.redis.nonpersistent.host,
                                   port=config.core.redis.nonpersistent.port)


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

    try:
        success, key, op = CLIENT.add_update(data, dedup_name)
        if success:
            signature_event_sender.send(data['type'], {
                'signature_id': data['signature_id'],
                'signature_type': data['type'],
                'source': data['source'],
                'operation': op
            })

        return make_api_response({"success": success, "id": key})

    except ValueError as e:
        message = str(e)
        resp_data = ""
        if "A signature with that name already exists" == message:
            resp_data = {"success": False}
        return make_api_response(resp_data, message, 400)


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

    try:
        res = CLIENT.add_update_many(source, sig_type, data, dedup_name)
        if res:
            signature_event_sender.send(sig_type, {
                'signature_id': '*',
                'signature_type': sig_type,
                'source': source,
                'operation': Operation.Modified
            })
        return make_api_response(res)
    except ValueError as e:
        return make_api_response("", str(e), 400)


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
    try:
        success, data = CLIENT.change_status(signature_id, status, user)
        signature_event_sender.send(data['type'], {
            'signature_id': signature_id,
            'signature_type': data['type'],
            'source': data['source'],
            'operation': Operation.Modified
        })
        return make_api_response({"success": success})
    except (ValueError, PermissionError) as e:
        make_api_response("", str(e), 403)
    except FileNotFoundError as e:
        make_api_response("", str(e), 404)


@signature_api.route("/clear_status/<signature_id>/", methods=["GET"])
@api_login(allow_readonly=False, require_role=[ROLES.signature_manage])
def clear_status(signature_id, **kwargs):
    """
    Clear the user's status change of a signature

    Variables:
    signature_id    =>  ID of the signature

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "success" : true }      #If saving the rule was a success or not
    """
    user = kwargs['user']

    while True:
        signature_obj, version = STORAGE.signature.get_if_exists(signature_id, as_obj=False, version=True)

        if not signature_obj:
            return make_api_response({"success": False}, "This signature was not found in the system.", 404)

        if not user or not Classification.is_accessible(user['classification'], signature_obj['classification']):
            return make_api_response({"success": False}, "You are not allowed to make changes to this signature...", 403)

        try:
            signature_obj['state_change_date'] = None
            signature_obj['state_change_user'] = None
            response = STORAGE.signature.save(signature_id, signature_obj, version=version)
            break
        except VersionConflictException as vce:
            LOGGER.info(f"Retrying saving signature due to version conflict: {str(vce)}")

    signature_event_sender.send(signature_obj['type'], {
        'signature_id': signature_id,
        'signature_type': signature_obj['type'],
        'source': signature_obj['source'],
        'operation': Operation.Modified
    })

    return make_api_response({"success": response})


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
        [service_updates.pop(k) for k in service_updates.keys() if k.startswith(f'{name}.')]

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

            rule_file_bin = CLIENT.download(query, access)

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
        for s in service['update_config']['sources']:
            # Update update_interval to default to globally configured value by updater
            if 'update_interval' not in s:
                s['update_interval'] = service['update_config']['update_interval_seconds']
        append_source_status(service)
        out[service['name']] = {key: service['update_config'][key] if key in service['update_config'] else None
                                for key in ['sources', 'generates_signatures', 'update_interval_seconds', 'default_pattern']}

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
      "pattern": "^*.yar$",                   # Regex pattern use to get appropriate files from the URI
      "override_classification": false        # Should the classification of the source override to signature classification?
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
                                 err=f"Could not found source '{data['name']}' in service {service}.",
                                 status_code=404)

    service_delta = STORAGE.service_delta.get(service, as_obj=False)
    if service_delta.get('update_config') is None:
        service_delta['update_config'] = {"sources": new_sources}
    else:
        service_delta['update_config']['sources'] = new_sources

    # Save the service changes
    success = STORAGE.service_delta.save(service, service_delta)

    if classification_changed or data['override_classification']:
        class_norm = Classification.normalize_classification(data['default_classification'])
        STORAGE.signature.update_by_query(query=f'source:"{data["name"]}"',
                                          operations=[("SET", "classification", class_norm),
                                                      ("SET", "last_modified", now_as_iso())])

        # Notify that signatures have changed (trigger local_update)
        signature_event_sender.send(service, {
            'signature_id': '*',
            'signature_type': service.lower(),
            'source': data['name'],
            'operation': Operation.Modified
        })

    # Clear the caching value and trigger an update in case there were any other changes made
    service_updates = Hash(f'service-updates-{service}', config.core.redis.persistent.host,
                            config.core.redis.persistent.port)
    service_updates.set(key=f'{data["name"]}.update_time', value=0)
    service_updates.set(key=f'{data["name"]}.status',
                        value=dict(state='UPDATING', message='Queued for update..', ts=now_as_iso()))

    # Notify that a source configuration has changes (trigger source_update)
    service_event_sender.send(service, {
        'operation': Operation.Modified,
        'name': service
    })
    return make_api_response({"success": success})

@signature_api.route("/sources/enable/<service>/<name>/", methods=["PUT"])
@api_login(allow_readonly=False, require_role=[ROLES.workflow_manage])
def set_signature_source_status(service, name, **_):
    """
    Set the enabled status of a signature source

    Variables:
    service         => Name of service that signature source belongs to
    name            => Name of signature source

    Arguments:
    None

    Data Block:
    {
     "enabled": "true"              # Enable or disable the signature source
    }

    Result example:
    {"success": True}
    """
    data = request.json
    enabled = data.get('enabled', None)
    status_changed = False
    if enabled is None:
        return make_api_response({"success": False}, err="Enabled field is required", status_code=400)
    else:
        service_data = STORAGE.get_service_with_delta(service, as_obj=False)
        current_sources = service_data.get('update_config', {}).get('sources', [])

        new_sources = []
        found = False
        for source in current_sources:
            if name == source['name']:
                status_changed = source['enabled'] != enabled
                source['enabled'] = enabled
                new_sources.append(source)
                found = True
            else:
                new_sources.append(source)

        if not found:
            return make_api_response({"success": False},
                                    err=f"Could not found source '{data['name']}' in service {service}.",
                                    status_code=404)

        service_delta = STORAGE.service_delta.get(service, as_obj=False)
        if service_delta.get('update_config') is None:
            service_delta['update_config'] = {"sources": new_sources}
        else:
            service_delta['update_config']['sources'] = new_sources

        success = STORAGE.service_delta.save(service, service_delta)

        if status_changed:
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
    last_update = request.args.get('last_update')

    return make_api_response({"update_available": CLIENT.update_available(last_update, sig_type)})
