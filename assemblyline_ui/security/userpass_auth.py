from ipaddress import ip_address, ip_network

import elasticapm
from assemblyline.common.security import verify_password
from flask import request, session

from assemblyline_ui.config import config
from assemblyline_ui.http_exceptions import AuthenticationException


@elasticapm.capture_span(span_type='authentication')
def validate_userpass(username, password, storage):
    # This function uses the internal authenticator to identify the user
    # You can overload this to pass username/password to an LDAP server for exemple
    if config.auth.internal.enabled and username and password:
        # Check if user is allowed to use internal auth from its IP
        ip = ip_address(session.get("ip", request.remote_addr))
        if config.auth.internal.ip_filter and not any(ip in ip_network(cidr) for cidr in config.auth.internal.ip_filter):
            raise AuthenticationException(f"Access from IP {ip} is not allowed for username/password login")

        user = storage.user.get(username)
        if user:
            if verify_password(password, user.password):
                return username

        raise AuthenticationException("Wrong username or password")

    return None
