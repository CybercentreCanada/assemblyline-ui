from typing import Any, Optional

from assemblyline_ui.config import AssemblylineDatastore, config
from assemblyline_ui.helper.user import get_dynamic_classification
from assemblyline.odm.models.user import TYPES, ROLES, load_roles


def validate_saml_user(username: str, saml_user_data: dict, storage: AssemblylineDatastore):

    if config.auth.saml.enabled and username and saml_user_data:
        cur_user = storage.user.get(username, as_obj=False) or {}

        # Make sure the user exists in AL and is in sync
        if (not cur_user and config.auth.saml.auto_create) or (cur_user and config.auth.saml.auto_sync):
            # Generate user data from SAML
            email: Any = _get_attribute(saml_user_data, config.auth.saml.attributes.email_attribute)
            if email is not None:
                email = email.lower()
            name = _get_attribute(saml_user_data, config.auth.saml.attributes.fullname_attribute) or username

            data = dict(
                uname=username,
                name=name,
                email=email,
                password="__NO_PASSWORD__"
            )

            # Get the user type from the SAML data
            data['type'] = _get_types(saml_user_data) or ['user']

            # Load in user roles or get the roles from the types
            user_roles = _get_roles(saml_user_data) or None
            data['roles'] = load_roles(data['type'], user_roles)

            # Load in the user DN
            if (dn := _get_attribute(saml_user_data, "dn")):
                data['dn'] = dn

            # Get the dynamic classification info
            if (u_classification := _get_attribute(saml_user_data, 'classification')):
                data["classification"] = get_dynamic_classification(u_classification, data)

            # Save the updated user
            cur_user.update(data)
            storage.user.save(username, cur_user)

        if cur_user:
            return username

    return None


def _get_types(data: dict) -> list:
    valid_types = TYPES.keys()
    valid_groups = config.auth.saml.attributes.group_type_mapping
    user_groups = _get_attribute(data, config.auth.saml.attributes.groups_attribute, False) or []
    user_types = [valid_groups[key].lower() for key in user_groups if key in valid_groups]
    return [
        user_type
        for user_type in user_types
        if user_type in valid_types
    ]


def _get_roles(data: dict) -> list:
    user_roles = _get_attribute(data, config.auth.saml.attributes.roles_attribute, False) or []
    return [
        ROLES.lookup(user_role)
        for user_role in user_roles
        if ROLES.lookup(user_role) is not None
    ]


def _get_attribute(data: dict, key: str, normalize: bool = True) -> Any:
    attribute = data.get(key)
    if normalize:
        attribute = _normalize_saml_attribute(attribute)
    return attribute


def _normalize_saml_attribute(attribute: Any) -> Optional[str]:
    # SAML attributes all seem to come through as lists
    if isinstance(attribute, list) and attribute:
        attribute = attribute[0]
    return attribute
