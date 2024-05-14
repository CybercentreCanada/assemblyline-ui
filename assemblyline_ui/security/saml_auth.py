from typing import Any, Optional

from assemblyline_ui.config import AssemblylineDatastore, config
from assemblyline_ui.helper.user import get_dynamic_classification
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline.odm.models.user import TYPES, ROLES


def validate_saml_user(username: str,
                       saml_user_data: dict,
                       storage: AssemblylineDatastore) -> (str, list[str]):

    if config.auth.saml.enabled and username:
        if saml_user_data:

            # TODO - not sure how we want to implement this, or if we even want
            # to. If they can log into SAML would we ever want to deny someone
            # access?
            # if not saml_user_data['access']:
            #     raise AuthenticationException("This user is not allowed access to the system")

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

                # Get the user type and roles
                if (type :=_get_types(saml_user_data)):
                    data['type'] = type
                if (roles := _get_attribute(saml_user_data, config.auth.saml.attributes.roles_attribute)):
                    data['roles'] = roles
                if (dn := _get_attribute(saml_user_data, "dn")):
                    data['dn'] = dn
                # Get the dynamic classification info
                if (u_classification := _get_attribute(saml_user_data, 'classification')):
                    data["classification"] = get_dynamic_classification(u_classification, data)

                # Save the updated user
                cur_user.update(data)
                storage.user.save(username, cur_user)

            if cur_user:
                # TODO - read roles from saml info?
                return username, ["R", "W"]
            else:
                raise AuthenticationException("User auto-creation is disabled")

        elif config.auth.internal.enabled:
            # Fallback to internal auth
            pass
        else:
            raise AuthenticationException("Bad SAML user data")

    return None

def _get_types(data: dict) -> list:
    valid_groups = config.auth.saml.attributes.group_type_mapping
    user_groups = _get_attribute(data, config.auth.saml.attributes.groups_attribute, False) or []
    user_types = [valid_groups[key].lower() for key in user_groups if key in valid_groups]
    return [
        TYPES.lookup(user_type) 
        for user_type in user_types
        if TYPES.lookup(user_type) is not None
    ]

def _get_roles(data: dict) -> list:
    user_roles = _get_attribute(data, config.auth.saml.attributes.roles_attribute, False) or []
    return [
        ROLES.lookup(user_role) 
        for user_role in user_roles
        if ROLES.lookup(user_role) is not None
    ]

def _get_attribute(data: dict, key: str, normalize: bool=True) -> Any:
    attribute = data.get(key)
    if normalize:
        attribute = _normalize_saml_attribute(attribute)
    return attribute

def _normalize_saml_attribute(attribute: Any) -> Optional[str]:
    # SAML attributes all seem to come through as lists
    if isinstance(attribute, list) and attribute:
        attribute = attribute[0]
    return attribute
