import yaml

from flask import request

from assemblyline.common import forge
from assemblyline.common.dict_utils import get_recursive_delta
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.hash import Hash
from assemblyline_core.updater.helper import get_latest_tag_for_service
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.api.v4.signature import _reset_service_updates
from assemblyline_ui.config import LOGGER, STORAGE

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'service'
service_api = make_subapi_blueprint(SUB_API, api_version=4)
service_api._doc = "Manage the different services"

latest_service_tags = Hash('service-tags', get_client(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    private=False,
))

service_update = Hash('container-update', get_client(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    private=False,
))


def check_private_keys(source_list):
    # Check format of private_key(if any) in sources
    for source in source_list:
        if source.get('private_key', None) and not source['private_key'].endswith("\n"):
            source['private_key'] += "\n"
    return source_list


def check_for_source_change(delta_list, source):
    change_list = {}
    for delta in delta_list:
        if delta['name'] == source['name']:
            # Classification update
            if delta['default_classification'] != source['default_classification']:
                class_norm = Classification.normalize_classification(delta['default_classification'])
                change_list['default_classification'] = STORAGE.signature.update_by_query(
                    query=f'source:"{source["name"]}"',
                    operations=[("SET", "classification", class_norm)])

    return change_list


def preprocess_sources(source_list):
    source_list = sanitize_source_names(source_list)
    source_list = check_private_keys(source_list)
    return source_list


def sanitize_source_names(source_list):
    for source in source_list:
        source['name'] = source['name'].replace(" ", "_")
    return source_list


def synchronize_sources(service_name, current_sources, new_sources):
    removed_sources = {}
    for source in current_sources:
        if source not in new_sources:
            # If not a minor change, then assume change is drastically different (ie. removal)
            if not check_for_source_change(new_sources, source):
                removed_sources[source['name']] = STORAGE.signature.delete_by_query(
                    f'type:"{service_name.lower()}" AND source:"{source["name"]}"')
    _reset_service_updates(service_name)
    return removed_sources


@service_api.route("/", methods=["PUT"])
@api_login(require_type=['admin'], allow_readonly=False)
def add_service(**_):
    """
    Add a service using its yaml manifest

    Variables:
    None

    Arguments:
    None

    Data Block:
    <service_manifest.yml content>

    Result example:
    { "success": true }  # Return true is the service was added
    """
    data = request.data

    try:
        if b"$SERVICE_TAG" in data:
            tmp_service = yaml.safe_load(data)
            tmp_service.pop('tool_version', None)
            tmp_service.pop('file_required', None)
            tmp_service.pop('heuristics', [])
            tmp_service['update_channel'] = config.services.preferred_update_channel
            image_name, tag_name, _ = get_latest_tag_for_service(Service(tmp_service), config, LOGGER)
            if tag_name:
                tag_name = tag_name.encode()
            else:
                tag_name = b'latest'

            data = data.replace(b"$SERVICE_TAG", tag_name)

        service = yaml.safe_load(data)
        # Pop the data not part of service model
        service.pop('tool_version', None)
        service.pop('file_required', None)
        heuristics = service.pop('heuristics', [])

        # Validate submission params
        for sp in service.get('submission_params', []):
            if sp['type'] == 'list' and 'list' not in sp:
                return make_api_response(
                    "", err=f"Missing list field for submission param: {sp['name']}", status_code=400)

            if sp['default'] != sp['value']:
                return make_api_response(
                    "", err=f"Default and value mismatch for submission param: {sp['name']}", status_code=400)

        # Fix update_channel with the system default
        service['update_channel'] = config.services.preferred_update_channel

        # Load service info
        service = Service(service)

        # Fix service version, we don't want to see stable if it's a stable container
        service.version = service.version.replace("stable", "")

        # Save service if it doesn't already exist
        if not STORAGE.service.get_if_exists(f'{service.name}_{service.version}'):
            STORAGE.service.save(f'{service.name}_{service.version}', service)
            STORAGE.service.commit()

        # Save service delta if it doesn't already exist
        if not STORAGE.service_delta.get_if_exists(service.name):
            STORAGE.service_delta.save(service.name, {'version': service.version})
            STORAGE.service_delta.commit()

        new_heuristics = []
        if heuristics:
            plan = STORAGE.heuristic.get_bulk_plan()
            for index, heuristic in enumerate(heuristics):
                try:
                    # Append service name to heuristic ID
                    heuristic['heur_id'] = f"{service.name.upper()}.{str(heuristic['heur_id'])}"

                    # Attack_id field is now a list, make it a list if we receive otherwise
                    attack_id = heuristic.get('attack_id', None)
                    if isinstance(attack_id, str):
                        heuristic['attack_id'] = [attack_id]

                    heuristic = Heuristic(heuristic)
                    heuristic_id = heuristic.heur_id
                    plan.add_upsert_operation(heuristic_id, heuristic)
                except Exception:
                    raise ValueError("Error parsing heuristics")

            for item in STORAGE.heuristic.bulk(plan)['items']:
                if item['update']['result'] != "noop":
                    new_heuristics.append(item['update']['_id'])

            STORAGE.heuristic.commit()

        return make_api_response(dict(
            service_name=service.name,
            new_heuristics=new_heuristics
        ))
    except ValueError as e:  # Catch errors when building Service or Heuristic model(s)
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/backup/", methods=["GET"])
@api_login(audit=False, require_type=['admin'], allow_readonly=False)
def backup(**_):
    """
    Create a backup of the current system configuration

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <SERVICE BACKUP>
    """
    services = {'type': 'backup', 'server': config.ui.fqdn, 'data': {}}

    for service in STORAGE.service_delta.stream_search("*:*", fl="id", as_obj=False):
        name = service['id']
        service_output = {
            'config': STORAGE.service_delta.get(name, as_obj=False),
            'versions': {}
        }
        for service_version in STORAGE.service.stream_search(f"name:{name}", fl="id", as_obj=False):
            version_id = service_version['id']
            service_output['versions'][version_id] = STORAGE.service.get(version_id, as_obj=False)

        services['data'][name] = service_output

    out = yaml.dump(services, indent=2)
    return make_file_response(
        out, name=f"{config.ui.fqdn}_service_backup.yml", size=len(out),
        content_type="application/json")


@service_api.route("/restore/", methods=["PUT", "POST"])
@api_login(audit=False, require_type=['admin'], allow_readonly=False)
def restore(**_):
    """
    Restore an old backup of the system configuration

    Variables:
    None

    Arguments:
    None

    Data Block:
    <SERVICE BACKUP>

    Result example:
    {'success': true}
    """
    data = request.data

    try:
        backup = yaml.safe_load(data)
        if "type" not in backup or "server" not in backup or "data" not in backup:
            return make_api_response("", err="Invalid service configuration backup.", status_code=400)

        if backup["server"] != config.ui.fqdn:
            return make_api_response(
                "", err="This backup was not created on this server, restore operation cancelled.", status_code=400)

        for service_name, service in backup['data'].items():
            # Grab the old value for a service
            old_service = STORAGE.get_service_with_delta(service_name, as_obj=False)

            # Restore the service
            for v_id, v_data in service['versions'].items():
                STORAGE.service.save(v_id, v_data)
            STORAGE.service_delta.save(service_name, service['config'])

            # Grab the new value for the service
            new_service = STORAGE.get_service_with_delta(service_name, as_obj=False)

            # Synchronize the sources if needed
            if old_service and old_service.get("update_config", {}).get("sources", None) is not None:
                synchronize_sources(service_name, old_service.get("update_config", {}).get(
                    "sources", []), new_service.get("update_config", {}).get("sources", []))

        return make_api_response({"success": True})
    except ValueError as e:
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/updates/", methods=["GET"])
@api_login(audit=False, require_type=['admin'], allow_readonly=False)
def check_for_service_updates(**_):
    """
        Check for potential updates for the given services.

        Variables:
        None

        Arguments:
        None

        Data Block:
        None

        Result example:
        {
          'ResultSample': {
            'latest_tag': 'v4.0.0dev163',
            'update_available': true
          }, ...
        }
    """
    output = {}

    for service in STORAGE.list_all_services(full=True, as_obj=False):
        update_info = latest_service_tags.get(service['name']) or {}
        if update_info:
            latest_tag = update_info.get(service['update_channel'], None)
            output[service['name']] = {
                "auth": update_info['auth'],
                "image": f"{update_info['image']}:{latest_tag or 'latest'}",
                "latest_tag": latest_tag,
                "update_available": latest_tag is not None and latest_tag.replace('stable', '') != service['version'],
                "updating": service_update.exists(service['name'])
            }

    return make_api_response(output)


@service_api.route("/constants/", methods=["GET"])
@api_login(audit=False, required_priv=['R'], allow_readonly=False)
def get_service_constants(**_):
    """
    Get global service constants.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "categories": [
          "Antivirus",
          "Extraction",
          "Static Analysis",
          "Dynamic Analysis"
        ],
        "stages": [
          "FILTER",
          "EXTRACT",
          "SECONDARY",
          "TEARDOWN"
        ]
    }
    """
    return make_api_response({
        'stages': config.services.stages,
        'categories': config.services.categories,
    })


@service_api.route("/versions/<servicename>/", methods=["GET"])
@api_login(require_type=['admin'], audit=False, allow_readonly=False)
def get_potential_versions(servicename, **_):
    """
    List the different versions of a service stored in the system

    Variables:
    servicename       => Name of the service to get the versions

    Arguments:
    None

    Data Block:
    None

    Result example:
    ['3.1.0', '3.2.0', '3.3.0', '4.0.0', ...]     # List of service versions
    """
    service = STORAGE.service_delta.get(servicename)
    if service:
        return make_api_response([item.version for item in
                                  STORAGE.service.search(f"id:{servicename}*", fl="version")['items']])
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/<servicename>/", methods=["GET"])
@api_login(require_type=['admin'], audit=False, allow_readonly=False)
def get_service(servicename, **_):
    """
    Load the configuration for a given service

    Variables:
    servicename       => Name of the service to get the info

    Arguments:
    version           => Specific version of the service to get

    Data Block:
    None

    Result example:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extracts some stuff"
     'enabled': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'timeout': 60}
    """
    version = request.args.get('version', None)

    service = STORAGE.get_service_with_delta(servicename, version=version, as_obj=False)
    if service:
        return make_api_response(service)
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/all/", methods=["GET"])
@api_login(audit=False, required_priv=['R'], allow_readonly=False)
def list_all_services(**_):
    """
    List all service configurations of the system.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
     [
        {'accepts': ".*"
         'category': 'Extraction',
         'classpath': 'al_services.alsvc_extract.Extract',
         'description': "Extracts some stuff",
         'enabled': True,
         'name': 'Extract',
         'rejects': 'empty'
         'stage': 'CORE'
         },
         ...
     ]
    """
    resp = [{'accepts': x.get('accepts', None),
             'category': x.get('category', None),
             'description': x.get('description', None),
             'enabled': x.get('enabled', False),
             'name': x.get('name', None),
             'rejects': x.get('rejects', None),
             'stage': x.get('stage', None),
             'version': x.get('version', None)}
            for x in STORAGE.list_all_services(full=True, as_obj=False)]

    return make_api_response(resp)


@service_api.route("/<servicename>/", methods=["DELETE"])
@api_login(require_type=['admin'], allow_readonly=False)
def remove_service(servicename, **_):
    """
    Remove a service configuration

    Variables:
    servicename       => Name of the service to remove

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": true}  # Has the deletion succeeded
    """
    svc = STORAGE.service_delta.get(servicename)

    if svc:
        success = True
        if not STORAGE.service_delta.delete(servicename):
            success = False
        if not STORAGE.service.delete_by_query(f"id:{servicename}*"):
            success = False
        STORAGE.heuristic.delete_by_query(f"{servicename.upper()}*")
        return make_api_response({"success": success})
    else:
        return make_api_response({"success": False},
                                 err=f"Service {servicename} does not exist",
                                 status_code=404)


@service_api.route("/<servicename>/", methods=["POST"])
@api_login(require_type=['admin'], allow_readonly=False)
def set_service(servicename, **_):
    """
    Calculate the delta between the original service config and
    the posted service config then saves that delta as the current
    service delta.

    Variables:
    servicename    => Name of the service to save

    Arguments:
    None

    Data Block:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extract some stuff",
     'enabled': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'timeout': 60}

    Result example:
    {"success": true }    #Saving the user info succeded
    """
    data = request.json
    version = data.get('version', None)
    if not version:
        return make_api_response({"success": False}, "The service you are trying to modify does not exist", 404)

    current_service = STORAGE.service.get(f"{servicename}_{version}", as_obj=False)

    if not current_service:
        return make_api_response({"success": False}, "The service you are trying to modify does not exist", 404)

    if 'name' in data and servicename != data['name']:
        return make_api_response({"success": False}, "You cannot change the service name", 400)

    # Do not allow user to edit the docker_config.image since we will use the default image for each versions
    data['docker_config']['image'] = current_service['docker_config']['image']
    delta = get_recursive_delta(current_service, data)
    delta['version'] = version

    removed_sources = {}
    # Check sources, especially to remove old sources
    if delta.get("update_config", {}).get("sources", None) is not None:
        delta["update_config"]["sources"] = preprocess_sources(delta["update_config"]["sources"])

        c_srcs = STORAGE.get_service_with_delta(servicename, as_obj=False).get('update_config', {}).get('sources', [])
        removed_sources = synchronize_sources(servicename, c_srcs, delta["update_config"]["sources"])

    return make_api_response({"success": STORAGE.service_delta.save(servicename, delta),
                              "removed_sources": removed_sources})


@service_api.route("/update/", methods=["PUT"])
@api_login(audit=False, require_type=['admin'], allow_readonly=False)
def update_service(**_):
    """
        Update a given service

        Variables:
        None

        Arguments:
        None

        Data Block:
        {
          "name": "ResultSample"
          "image": "cccs/assemblyline-service-resultsample:4.0.0dev0"
        }

        Result example:
        {
          success: true
        }
    """
    data = request.json
    service_key = f"{data['name']}_{data['update_data']['latest_tag'].replace('stable', '')}"

    # Check is the version we are trying to update to already exists
    if STORAGE.service.get_if_exists(service_key):
        operations = [(STORAGE.service_delta.UPDATE_SET, 'version',
                       data['update_data']['latest_tag'].replace('stable', ''))]
        if STORAGE.service_delta.update(data['name'], operations):
            return make_api_response({'success': True, 'status': "updated"})

    service_update.set(data['name'], data['update_data'])
    return make_api_response({'success': True, 'status': "updating"})
