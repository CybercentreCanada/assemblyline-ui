from assemblyline.common.isotime import epoch_to_iso, now_as_iso
from assemblyline.remote.datatypes.hash import Hash

from assemblyline_ui.config import config


def append_source_status(service: dict):
    if not service.get("update_config", None):
        # Service doesn't contain an update configuration
        return

    service_updates = Hash(f'service-updates-{service["name"]}', config.core.redis.persistent.host,
                           config.core.redis.persistent.port)
    for src in service['update_config']['sources']:
        # Included the current status of source to be rendered
        src['status'] = service_updates.get(f'{src["name"]}.status') or \
            {'state': 'UNKNOWN', 'message': 'Waiting for next update..', 'ts': now_as_iso()}
        src['status']['last_successful_update'] = epoch_to_iso(
            service_updates.get(f"{src['name']}.update_time") or 0)

def preprocess_sources(source_list):
    source_list = sanitize_source_names(source_list)
    source_list = check_private_keys(source_list)

    # Strip out any fields where the value is an empty string before saving delta
    for source in source_list:
        for key in list(source.keys()):
            if isinstance(source[key], str) and source[key] == "":
                source.pop(key)

    return source_list

def check_private_keys(source_list):
    # Check format of private_key(if any) in sources
    for source in source_list:
        if source.get("private_key", None) and not source["private_key"].endswith("\n"):
            source["private_key"] += "\n"
    return source_list

def sanitize_source_names(source_list):
    for source in source_list:
        source["name"] = source["name"].replace(" ", "_")
    return source_list
