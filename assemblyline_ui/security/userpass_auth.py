import elasticapm

from assemblyline_ui.config import config
from assemblyline.common.security import verify_password
from assemblyline_ui.http_exceptions import AuthenticationException


@elasticapm.capture_span(span_type='authentication')
def validate_userpass(username, password, storage):
    # This function uses the internal authenticator to identify the user
    # You can overload this to pass username/password to an LDAP server for exemple
    if config.auth.internal.enabled and username and password:
        user = storage.user.get(username)
        if user:
            if verify_password(password, user.password):
                return username

        raise AuthenticationException("Wrong username or password")

    return None
