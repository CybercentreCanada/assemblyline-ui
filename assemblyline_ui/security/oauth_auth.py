from assemblyline_ui.config import config, get_token_store
from assemblyline_ui.http_exceptions import AuthenticationException


def validate_oauth(username, oauth_token):
    # This function identifies the user via the internal API key functionality
    #   NOTE: It is not recommended to overload this function but you can still do it
    if config.auth.oauth.enabled and oauth_token:
        if get_token_store(username).exist(oauth_token):
            return username, ["R", "W", "E"]

        raise AuthenticationException("Invalid token")

    return None, None
