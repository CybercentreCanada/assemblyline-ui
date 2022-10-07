from assemblyline.common.isotime import now_as_iso, epoch_to_iso
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
