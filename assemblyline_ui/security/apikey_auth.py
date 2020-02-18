from assemblyline_ui.config import config
from assemblyline.common.security import verify_password
from assemblyline_ui.http_exceptions import AuthenticationException


def validate_apikey(username, apikey, storage):
    # This function identifies the user via the internal API key functionality
    #   NOTE: It is not recommended to overload this function but you can still do it
    if config.auth.allow_apikeys and apikey:
        user_data = storage.user.get(username)
        if user_data:
            name, apikey_password = apikey.split(":", 1)
            key = user_data.apikeys.get(name, None)
            if key is not None:
                if verify_password(apikey_password, key.password):
                    return username, key.acl

        raise AuthenticationException("Invalid apikey")

    return None, None
