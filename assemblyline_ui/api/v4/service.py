
import json
import re
import yaml

from flask import request
from math import floor
from packaging.version import parse

from assemblyline.common.dict_utils import get_recursive_delta
from assemblyline.common.version import FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.odm.models.error import ERROR_TYPES
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.service import Service
from assemblyline.odm.models.user import ROLES
from assemblyline.odm.messages.changes import Operation
from assemblyline.remote.datatypes import get_client
from assemblyline.remote.datatypes.events import EventSender
from assemblyline.remote.datatypes.hash import Hash
from assemblyline_core.updater.helper import get_latest_tag_for_service
from assemblyline_ui.api.base import api_login, make_api_response, make_file_response, make_subapi_blueprint
from assemblyline_ui.config import LOGGER, STORAGE, config, CLASSIFICATION as Classification
from assemblyline_ui.helper.signature import append_source_status

SUB_API = 'service'
service_api = make_subapi_blueprint(SUB_API, api_version=4)
service_api._doc = "Manage the different services"

latest_service_tags = Hash('service-tags', get_client(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    private=False,
))

service_install = Hash('container-install', get_client(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    private=False,
))

service_update = Hash('container-update', get_client(
    host=config.core.redis.persistent.host,
    port=config.core.redis.persistent.port,
    private=False,
))

event_sender = EventSender('changes.services',
                           host=config.core.redis.nonpersistent.host,
                           port=config.core.redis.nonpersistent.port)

root_event_sender = EventSender('changes',
                                host=config.core.redis.nonpersistent.host,
                                port=config.core.redis.nonpersistent.port)


def check_private_keys(source_list):
    # Check format of private_key(if any) in sources
    for source in source_list:
        if source.get('private_key', None) and not source['private_key'].endswith("\n"):
            source['private_key'] += "\n"
    return source_list


def source_exists(delta_list, source):
    exists = False
    for delta in delta_list:
        if delta['name'] == source['name']:
            exists = True
            # Classification update, perform an update-by-query
            if delta['default_classification'] != source['default_classification']:
                class_norm = Classification.normalize_classification(delta['default_classification'])
                STORAGE.signature.update_by_query(query=f'source:"{source["name"]}"',
                                                  operations=[("SET", "classification", class_norm)])

    return exists


def get_service_stats(service_name, version=None, max_docs=500):
    # Build query
    query = f'response.service_name:{service_name}'
    filters = []
    if version:
        try:
            framework, major, minor, build = version.replace('stable', '').split('.')
            if 'dev' not in build:
                filters.append(f'response.service_version:{framework}.{major}.{minor}.{build} OR '
                               f'response.service_version:{framework}.{major}.{minor}.stable{build}')
            else:
                filters.append(f'response.service_version:{version}')
        except Exception:
            filters.append(f'response.service_version:{version}')

    # Get default heuristic set
    heuristics = {
        h['heur_id']: 0
        for h in STORAGE.heuristic.stream_search(f'heur_id:{service_name.upper()}.*', fl='heur_id', as_obj=False)}

    # Get error type distribution
    errors = {k: 0 for k in ERROR_TYPES.keys()}
    errors.update(STORAGE.error.facet('type', query=query, filters=filters))

    res = STORAGE.result.search(query, filters=filters, fl='created', sort="created desc", rows=max_docs, as_obj=False)
    if len(res['items']) == 0:
        # We have no document, quickly return empty stats
        data = {
            "error": errors,
            "file": {
                "extracted": {"avg": 0, "max": 0, "min": 0},
                "supplementary": {"avg": 0, "max": 0, "min": 0}
            },
            "heuristic": heuristics,
            "result": {
                "count": 0,
                "score": {
                    "avg": 0,
                    "distribution": {"0": 0, "500": 0},
                    "max": 0,
                    "min": 0
                }
            },
            'service': {'name': service_name}
        }
    else:
        # Otherwise add a filter to limit the stats to the last max_docs entries
        filters.append(f"created:[{res['items'][-1]['created']} TO {res['items'][0]['created']}]")

        # Generate score stats
        score_stats = {k: v or 0 for k, v in STORAGE.result.stats('result.score', query=query, filters=filters).items()}
        score_stats.pop('sum', None)

        # Count number of results
        result_count = score_stats.pop('count')

        # Set score gap, min and max
        gap = 500
        min_score = floor(score_stats['min']/gap)*gap
        max_score = floor(score_stats['max']/gap)*gap + gap

        # Build score distribution
        score_stats['distribution'] = STORAGE.result.histogram(
            'result.score', start=min_score, end=max_score, gap=gap, mincount=0,
            query=query, filters=filters)

        # Get heuristic count
        heuristics.update(STORAGE.result.facet('result.sections.heuristic.heur_id', query=query, filters=filters))

        # Get extracted files count
        extracted = {k: v or 0 for k, v in STORAGE.result.stats(
            'response.extracted.length', query=query, filters=filters,
            field_script="params._source.response.extracted.length").items()}
        extracted.pop('count')
        extracted.pop('sum')

        # Get supplementary files count
        supplementary = {k: v or 0 for k, v in STORAGE.result.stats(
            'response.supplementary.length', query=query, filters=filters,
            field_script="params._source.response.supplementary.length").items()}
        supplementary.pop('count')
        supplementary.pop('sum')

        data = {
            'service': {'name': service_name},
            'error': errors,
            'file': {
                'extracted': extracted,
                'supplementary': supplementary
            },
            'heuristic': heuristics,
            'result': {
                'count': result_count,
                'score': score_stats
            }
        }

    if version:
        data['service']['version'] = version

    return data


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
            # If the source doesn't exist in the set of new sources, assume deletion and cleanup
            if not source_exists(new_sources, source):
                removed_sources[source['name']] = STORAGE.signature.delete_by_query(
                    f'type:"{service_name.lower()}" AND source:"{source["name"]}"') != 0
                service_updates = Hash(f'service-updates-{service_name}', config.core.redis.persistent.host,
                                       config.core.redis.persistent.port)
                [service_updates.pop(k) for k in service_updates.keys() if k.startswith(f'{source["name"]}.')]

            # Notify of changes to updater
            EventSender('changes.signatures',
                        host=config.core.redis.nonpersistent.host,
                        port=config.core.redis.nonpersistent.port).send(service_name.lower(), {
                            'signature_id': '*',
                            'signature_type': service_name.lower(),
                            'source': source["name"],
                            'operation': Operation.Removed
                        })

    return removed_sources


@service_api.route("/", methods=["PUT"])
@api_login(require_role=[ROLES.administration], allow_readonly=False)
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
    enable_allowed = True
    try:
        if b"$SERVICE_TAG" in data:
            tmp_data = yaml.safe_load(data)

            # Stash non-Service related fields to include back into data blob
            non_service_fields = {
                'tool_version': tmp_data.pop('tool_version', None),
                'file_required': tmp_data.pop('file_required', None),
                'heuristics': tmp_data.pop('heuristics', [])
            }

            # Apply global preferences, if missing, to get the appropriate container image tags
            if not tmp_data.get('update_channel'):
                tmp_data['update_channel'] = config.services.preferred_update_channel

            if not tmp_data['docker_config'].get('registry_type'):
                tmp_data['docker_config']['registry_type'] = config.services.preferred_registry_type

            # Create a Service object
            tmp_service = Service(tmp_data)

            _, tag_name, _ = get_latest_tag_for_service(tmp_service, config, LOGGER)
            enable_allowed = bool(tag_name)
            tag_name = tag_name.encode() if tag_name else b'latest'

            # Ensure any updates to Service's docker_config details get propagated
            tmp_data['docker_config'].update(tmp_service.docker_config.as_primitives())
            tmp_data.update(non_service_fields)
            data = json.dumps(tmp_data).encode()

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

        # Apply default global configurations (if absent in service configuration)
        if not service.get('update_channel'):
            service['update_channel'] = config.services.preferred_update_channel
        if not service.get('docker_config', {}).get('registry_type'):
            service['docker_config']['registry_type'] = config.services.preferred_registry_type

        # Privilege can be set explicitly but also granted to services that don't require the file for analysis
        service['privileged'] = service.get('privileged', config.services.prefer_service_privileged)

        for dep in service.get('dependencies', {}).values():
            dep['container']['registry_type'] = dep.get('registry_type', config.services.preferred_registry_type)
        service['enabled'] = service['enabled'] and enable_allowed

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

        # Notify components watching for service config changes
        event_sender.send(service.name, {
            'operation': Operation.Added,
            'name': service.name
        })

        new_heuristics = []
        if heuristics:
            plan = STORAGE.heuristic.get_bulk_plan()
            for _, heuristic in enumerate(heuristics):
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

            # Notify components watching for heuristic changes
            root_event_sender.send('heuristics', {
                'operation': Operation.Modified,
                'service_name': service.name,
            })

        return make_api_response(dict(
            service_name=service.name,
            new_heuristics=new_heuristics
        ))
    except ValueError as e:  # Catch errors when building Service or Heuristic model(s)
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/backup/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
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
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
def restore(**_):
    """
    Restore an old backup of the system configuration

    Variables:
    None

    Arguments:
    None

    Data Block:

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

            # Notify components watching for service config changes
            event_sender.send(service_name, {
                'operation': Operation.Added if old_service else Operation.Removed,
                'name': service_name
            })

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
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
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
@api_login(audit=False, allow_readonly=False)
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
@api_login(require_role=[ROLES.administration], audit=False, allow_readonly=False)
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
    service = STORAGE.get_service_with_delta(servicename)
    if service:
        if service.update_channel != 'stable':
            version_re = f"{FRAMEWORK_VERSION}\\.{SYSTEM_VERSION}\\.\\d+\\.{service.update_channel}\\d+"
        else:
            version_re = f"{FRAMEWORK_VERSION}\\.{SYSTEM_VERSION}\\.\\d+\\.\\w+"

        versions = [
            item.version
            for item in STORAGE.service.stream_search(f"id:{servicename}*", fl="version")
            if re.match(version_re, item.version)
        ]

        return make_api_response(sorted(versions, key=lambda x: parse(x), reverse=True))
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/<servicename>/", methods=["GET"])
@api_login(require_role=[ROLES.administration], audit=False, allow_readonly=False)
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
    append_source_status(service)
    if service:
        return make_api_response(service)
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/<servicename>/<version>/", methods=["GET"])
@api_login(require_role=[ROLES.administration], audit=False, allow_readonly=False)
def get_service_defaults(servicename, version, **_):
    """
    Load the default configuration for a given service version

    Variables:
    servicename       => Name of the service to get the info
    version           => Version of the service to get

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
    service = STORAGE.service.get(f"{servicename}_{version}", as_obj=False)
    append_source_status(service)
    if service:
        return make_api_response(service)
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/all/", methods=["GET"])
@api_login(audit=False, allow_readonly=False)
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
             'privileged': x.get('privileged', False),
             'rejects': x.get('rejects', None),
             'stage': x.get('stage', None),
             'version': x.get('version', None)}
            for x in STORAGE.list_all_services(full=True, as_obj=False)]

    return make_api_response(resp)


@service_api.route("/<servicename>/", methods=["DELETE"])
@api_login(require_role=[ROLES.administration], allow_readonly=False)
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
        STORAGE.heuristic.delete_by_query(f"id:{servicename.upper()}*")
        STORAGE.signature.delete_by_query(f"type:{servicename.lower()}*")

        # Notify components watching for service config changes
        event_sender.send(servicename, {
            'operation': Operation.Removed,
            'name': servicename
        })

        # Clear potentially unused keys from Redis related to service
        Hash(f'service-updates-{servicename}', get_client(
            host=config.core.redis.persistent.host,
            port=config.core.redis.persistent.port,
            private=False,
        )).delete()

        return make_api_response({"success": success})
    else:
        return make_api_response({"success": False},
                                 err=f"Service {servicename} does not exist",
                                 status_code=404)


@service_api.route("/<servicename>/", methods=["POST"])
@api_login(require_role=[ROLES.administration], allow_readonly=False)
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

    current_default = STORAGE.service.get(f"{servicename}_{version}", as_obj=False)
    current_service = STORAGE.get_service_with_delta(servicename, as_obj=False)

    if not current_default:
        return make_api_response({"success": False}, "The service you are trying to modify does not exist", 404)

    if 'name' in data and servicename != data['name']:
        return make_api_response({"success": False}, "You cannot change the service name", 400)

    if current_service['version'] != version:
        # On version change, reset all container versions
        data['docker_config']['image'] = current_default['docker_config']['image']
        for k, v in data['dependencies'].items():
            if k in current_default['dependencies']:
                v['container']['image'] = current_default['dependencies'][k]['container']['image']

    delta = get_recursive_delta(current_default, data, stop_keys=['config'])
    delta['version'] = version

    removed_sources = {}
    # Check sources, especially to remove old sources
    if delta.get("update_config", {}).get("sources", None) is not None:
        delta["update_config"]["sources"] = preprocess_sources(delta["update_config"]["sources"])

        c_srcs = current_service.get('update_config', {}).get('sources', [])
        removed_sources = synchronize_sources(servicename, c_srcs, delta["update_config"]["sources"])

    # Notify components watching for service config changes
    success = STORAGE.service_delta.save(servicename, delta)

    if success:
        event_sender.send(servicename, {
            'operation': Operation.Modified,
            'name': servicename
        })

    return make_api_response({"success": success,
                              "removed_sources": removed_sources})


@service_api.route("/installing/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
def get_services_installing(**_):
    """
        Get the list of services currently being installed.

        Variables:
        None

        Arguments:
        None

        Data Block:
        None

        Result example:

        # List of services being installed
        ["ResultSample"]
    """
    try:
        services = set(STORAGE.service_delta.keys())
        output = [name for name in service_install.items() if name not in services]

        return make_api_response(output)
    except ValueError as e:
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/installing/", methods=["POST"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
def post_services_installing(**_):
    """
        Get the list of services currently being installed.

        Variables:
        None

        Arguments:
        None

        Data Block:
        [
            <LIST OF SERVICE NAMES>
        ]

        Result example:
        {
          "installed":      [ "ResultSample" ],     # List of services that were installed
          "installing":     [ "ExtraFeature" ],     # List of services being installed
          "not_installed":  ["rejectedFeature"]     # List of services that are not installed
        }
    """

    try:
        names = request.json
        output = {'installing': [], 'installed': [], 'not_installed': []}

        if isinstance(names, (list, tuple)):
            services = set(STORAGE.service_delta.keys())
            installing = service_install.items()

            for name in names:
                if name in services:
                    output['installed'].append(name)

                elif name in installing:
                    output['installing'].append(name)

                else:
                    output['not_installed'].append(name)

        return make_api_response(output)
    except ValueError as e:  # Catch errors when building Service or Heuristic model(s)
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/install/", methods=["PUT"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
def install_services(**_):
    """
        Install multiple services from a list provided as data

        Variables:
        None

        Arguments:
        None

        Data Block:
        [{
            "name": "ResultSample"
            "image": "cccs/assemblyline-service-resultsample"
        }]

        Result example:
        [ "ExtraFeature" ]     # List of services being installed
    """

    try:
        services = request.json
        output = []

        if not isinstance(services, list):
            return make_api_response("", err="Invalid data sent to install API", status_code=400)

        installed_services = set(STORAGE.service_delta.keys())

        for service in services:
            if service["name"] not in installed_services:
                image = service['image']
                install_data = {
                    'image': f"${{REGISTRY}}{image}" if not image.startswith("$") else image
                }
                service_install.set(service["name"], install_data)
                output.append(service["name"])

        return make_api_response(output)
    except ValueError as e:  # Catch errors when building Service or Heuristic model(s)
        return make_api_response("", err=str(e), status_code=400)


@service_api.route("/update/", methods=["PUT"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
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
            event_sender.send(data['name'], {
                'operation': Operation.Modified,
                'name': data['name']
            })
            return make_api_response({'success': True, 'status': "updated"})

    service_update.set(data['name'], data['update_data'])
    return make_api_response({'success': True, 'status': "updating"})


@service_api.route("/update_all/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.administration], allow_readonly=False)
def update_all_services(**_):
    """
        Update all service that require an update

        Variables:
        None

        Arguments:
        None

        Data Block:
        None

        Result example:
        {
          "updated": [ "ResultSample" ],    # List of services that were updated
          "updating": [ "ExtraFeature" ]    # List of service being updated
        }
    """
    output = {"updating": [], "updated": []}
    for service in STORAGE.list_all_services(full=True, as_obj=False):
        name = service['name']
        update_info = latest_service_tags.get(name) or {}
        latest_tag = update_info.get(service['update_channel'], None)
        clean_latest_tag = latest_tag.replace('stable', '') if latest_tag is not None else latest_tag
        srv_update_available = latest_tag is not None and clean_latest_tag != service['version']
        srv_updating = service_update.exists(name)
        if srv_update_available and not srv_updating:
            # Check is the version we are trying to update to already exists
            if STORAGE.service.get_if_exists(f"{name}_{clean_latest_tag}"):
                operations = [(STORAGE.service_delta.UPDATE_SET, 'version', clean_latest_tag)]
                if STORAGE.service_delta.update(name, operations):
                    event_sender.send(name, {
                        'operation': Operation.Modified,
                        'name': name
                    })
                    output['updated'].append(name)
            else:
                service_update.set(name, {
                    "auth": update_info['auth'],
                    "image": f"{update_info['image']}:{latest_tag or 'latest'}",
                    "latest_tag": latest_tag,
                    "update_available": srv_update_available,
                    "updating": srv_updating
                })
                output['updating'].append(name)

    return make_api_response(output)


@service_api.route("/stats/<service_name>/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.administration])
def service_statistics(service_name, **_):
    """
        Get statistics for a service

        Variables:
        None

        Arguments:
        version    =>   Version of the service to get stats for
        max_docs   =>   Maximum number of results to generate the stats on
                        (Default: 500)

        Data Block:
        None

        Result example:
        {'error': {
           'EXCEPTION': 4,
           'MAX DEPTH REACHED': 0,
           'MAX FILES REACHED': 0,
           'MAX RETRY REACHED': 0,
           'SERVICE BUSY': 0,
           'SERVICE DOWN': 0,
           'TASK PRE-EMPTED': 0,
           'UNKNOWN': 0},
        'file': {
           'extracted': {'avg': 1.064516129032258, 'max': 3.0, 'min': 0.0},
           'supplementary': {'avg': 5.967741935483871, 'max': 15.0, 'min': 1.0}},
        'heuristic': {
            'RESULTSAMPLE.1': 15,
            'RESULTSAMPLE.2': 14,
            'RESULTSAMPLE.3': 14,
            'RESULTSAMPLE.4': 16,
            'RESULTSAMPLE.5': 11,
            'RESULTSAMPLE.6': 3},
        'result': {'count': 31,
        'score': {'avg': 692.9032258064516,
                  'distribution': {0: 17,
                                   500: 0,
                                   1000: 3,
                                   1500: 11,
                                   2000: 0},
                  'max': 1910.0,
                  'min': 0.0}},
        'service': {'name': 'ResultSample', 'version': '4.2.0.dev0'}}
    """
    version = request.args.get('version', None)
    max_docs = int(request.args.get('max_docs', 500))
    return make_api_response(get_service_stats(service_name, version=version, max_docs=max_docs))
