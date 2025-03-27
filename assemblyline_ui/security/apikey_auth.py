from assemblyline.common.isotime import format_time, now_as_utc_datetime, trunc_day
import elasticapm

from assemblyline.odm.models.user import load_roles_form_acls, ROLES, load_roles
from assemblyline_ui.config import config
from assemblyline.common.security import verify_password
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline.odm.models.apikey import get_apikey_id

@elasticapm.capture_span(span_type='authentication')
def validate_apikey(username, apikey, storage):
    # This function identifies the user via the internal API key functionality
    #   NOTE: It is not recommended to overload this function but you can still do it
    if not config.auth.allow_apikeys and apikey:
        raise AuthenticationException("APIKey login is disabled")

    if config.auth.allow_apikeys and apikey:
        user_data = storage.user.get(username)

        if user_data:
            if ROLES.apikey_access not in load_roles(user_data.type, user_data.roles):
                raise AuthenticationException("This user is not allow to use API Keys")
            if not user_data.is_active:
                raise AuthenticationException("This owner of this API Key is not active.")

            try:
                name, apikey_password = apikey.split(":", 1)
                key_id = get_apikey_id(name, username)
                key = storage.apikey.get(key_id)

                if key:
                    if verify_password(apikey_password, key.password):
                        # Load user and API key roles
                        apikey_roles_limit = load_roles_form_acls(key.acl, key.roles)
                        old_last_used = key.last_used
                        current_date = format_time(trunc_day(now_as_utc_datetime()))

                        if old_last_used != current_date:
                            key.last_used = current_date
                            storage.apikey.save(key_id, key)
                        return username, apikey_roles_limit

            except ValueError:
                pass

        raise AuthenticationException("Invalid user or APIKey")

    return None, None
