from typing import Optional

from assemblyline.common.isotime import format_time, now_as_iso, now_as_utc_datetime, trunc_day
import elasticapm

from assemblyline.odm.models.user import load_roles_form_acls, ROLES, load_roles
from assemblyline_ui.config import config
from assemblyline.common.security import verify_password
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline.odm.models.apikey import get_apikey_id


@elasticapm.capture_span(span_type='authentication')
def validate_apikey(
    username: str,
    apikey: Optional[str],
    storage,
    skip_verification: bool = False
) -> tuple[Optional[str], Optional[list[str]]]:
    """Validate an API key for the given username."""
    if not config.auth.allow_apikeys:
        if apikey:
            raise AuthenticationException("APIKey login is disabled")
        return None, None

    if not apikey:
        return None, None

    user_data = storage.user.get(username)
    if not user_data:
        raise AuthenticationException("Invalid user or APIKey")

    user_roles = load_roles(user_data.type, user_data.roles)
    if ROLES.apikey_access not in user_roles:
        raise AuthenticationException("This user is not allowed to use API Keys")

    if not user_data.is_active:
        raise AuthenticationException("The owner of this API Key is not active.")

    try:
        key_name, apikey_password = apikey.split(":", 1)
    except ValueError:
        raise AuthenticationException("Invalid user or APIKey")

    key_id = get_apikey_id(key_name, username)
    key = storage.apikey.get(key_id)
    if not key:
        raise AuthenticationException("Invalid user or APIKey")

    password_valid = skip_verification or verify_password(apikey_password, key.password)
    if not password_valid:
        raise AuthenticationException("Invalid user or APIKey")

    apikey_roles_limit = load_roles_form_acls(key.acl, key.roles)

    if not skip_verification:
        _update_key_last_used(storage, key, key_id)

    return username, apikey_roles_limit


def _update_key_last_used(storage, key, key_id: str) -> None:
    """Update the last_used timestamp on the API key if a day has passed."""
    current_date = now_as_utc_datetime()
    old_last_used = format_time(trunc_day(key.last_used)) if key.last_used else None

    if old_last_used != format_time(trunc_day(current_date)):
        key.last_used = now_as_iso()
        storage.apikey.save(key_id, key)
