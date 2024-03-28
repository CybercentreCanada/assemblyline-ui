from typing import Any

from assemblyline_ui.config import AssemblylineDatastore, config
from assemblyline_ui.http_exceptions import AuthenticationException


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

                email: Any = saml_user_data.get(config.auth.saml.email_attribute_name)
                last_name: Any = saml_user_data.get(config.auth.saml.last_name_attribute_name)
                first_name: Any = saml_user_data.get(config.auth.saml.first_name_attribute_name)

                email: str = _normalize_saml_attribute(email).lower()
                last_name: str = _normalize_saml_attribute(last_name)
                first_name: str = _normalize_saml_attribute(first_name)

                # Generate user data from SAML
                data = dict(uname=username,
                            name=f"{last_name}, {first_name}",
                            email=email,
                            password="__NO_PASSWORD__",
                            )
                # TODO - These exist in LDAP, not sure what it's used for
                #     classification=saml_user_data.get("classification"),
                #     type=saml_user_data.get("type"),
                #     roles=saml_user_data.get("roles",
                #     dn=saml_user_data.get("dn")

                # TODO
                # # Get the dynamic classification info
                # data["classification"] = get_dynamic_classification(u_classification, data)

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


def _normalize_saml_attribute(attribute: Any) -> str:
    # SAML attributes all seem to come through as lists
    if isinstance(attribute, list) and attribute:
        attribute = attribute[0]
    return str(attribute or "")
