from typing import Any, Optional

from assemblyline.odm.models.user import ROLES, TYPES
from assemblyline_ui.config import config, get_token_store
from assemblyline_ui.http_exceptions import AuthenticationException


def validate_saml_user(username: str, saml_token_id: str):
    # This function identifies the user via a saved saml_token_id in redis
    if not config.auth.saml.enabled and saml_token_id:
        raise AuthenticationException("SAML login is disabled")

    if config.auth.saml.enabled and saml_token_id:
        if get_token_store(username, 'saml').exist(saml_token_id):
            return username

        raise AuthenticationException("Invalid token")

    return None


def get_types(data: dict) -> list:
    valid_types = TYPES.keys()
    valid_groups = config.auth.saml.attributes.group_type_mapping
    user_groups = get_attribute(data, config.auth.saml.attributes.groups_attribute, False) or []
    user_types = [valid_groups[key].lower() for key in user_groups if key in valid_groups]
    return [
        user_type
        for user_type in user_types
        if user_type in valid_types
    ]


def get_roles(data: dict) -> list:
    # Return the intersection of the user's roles and the roles defined in the system
    user_roles = get_attribute(data, config.auth.saml.attributes.roles_attribute, False) or []
    return list(set(ROLES.keys()).intersection(user_roles))


def get_attribute(data: dict, key: str, normalize: bool = True) -> Any:
    attribute = data.get(key)
    if normalize:
        attribute = _normalize_saml_attribute(attribute)
    return attribute


def _normalize_saml_attribute(attribute: Any) -> Optional[str]:
    # SAML attributes all seem to come through as lists
    if isinstance(attribute, list) and attribute:
        attribute = attribute[0]
    return attribute
