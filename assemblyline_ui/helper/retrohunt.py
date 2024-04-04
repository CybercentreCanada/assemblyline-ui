from typing import Optional

from assemblyline.odm.models.config import Config
from hauntedhouse import Client


def get_hauntedhouse_client(config: Config) -> Optional[Client]:
    if config.retrohunt.enabled:
        ca_path = None
        if config.retrohunt.tls_verify:
            ca_path = '/etc/assemblyline/ssl/al_root-ca.crt'

        return Client(
            address=config.retrohunt.url,
            api_key=config.retrohunt.api_key,
            verify=ca_path
        )
    return None
