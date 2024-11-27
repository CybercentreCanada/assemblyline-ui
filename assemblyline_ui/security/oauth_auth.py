import elasticapm
import jwt
import requests

from copy import copy

from assemblyline.odm.models.user import load_roles_form_acls
from assemblyline_ui.config import config, get_token_store, STORAGE, CACHE, LOGGER
from assemblyline_ui.helper.oauth import get_profile_identifiers
from assemblyline_ui.http_exceptions import AuthenticationException


@elasticapm.capture_span(span_type='authentication')
def get_jwks_keys(url):
    cache_key = CACHE.create_key("jwks", url)
    jwks = CACHE.get(cache_key, reset=False)

    # Go get it is not in cache
    if not jwks:
        jwks = requests.get(url).json()

        # Save it to the cache
        CACHE.set(cache_key, jwks, ttl=600)

    return jwks["keys"]


@elasticapm.capture_span(span_type='authentication')
def validate_oauth_id(username, oauth_token_id):
    # This function identifies the user via a saved oauth_token_id in redis
    if not config.auth.oauth.enabled and oauth_token_id:
        raise AuthenticationException("oAuth login is disabled")

    if config.auth.oauth.enabled and oauth_token_id:
        if get_token_store(username, 'oauth').exist(oauth_token_id):
            return username

        raise AuthenticationException("Invalid token")

    return None


@elasticapm.capture_span(span_type='authentication')
def validate_oauth_token(oauth_token, oauth_provider, return_user=False):
    # This function identifies the user via an externally provided oauth token
    if not config.auth.oauth.enabled and oauth_token and oauth_provider:
        raise AuthenticationException("oAuth login is disabled")

    if config.auth.oauth.enabled and oauth_token and oauth_provider:
        oauth_provider_config = config.auth.oauth.providers.get(oauth_provider, None)

        if not oauth_provider_config:
            raise AuthenticationException(f"Invalid oAuth provider: {oauth_provider}")

        if not oauth_provider_config.allow_external_tokens:
            raise AuthenticationException(f"External tokens are not accepted for oAuth provider: {oauth_provider}")

        if not oauth_provider_config.jwks_uri:
            raise AuthenticationException(f"oAuth provider '{oauth_provider}' does not have a jwks_uri configured.")

        # Gather provider valid audiences
        audiences = copy(oauth_provider_config.external_token_alternate_audiences)
        audiences.append(oauth_provider_config.client_id)

        # Find proper signing key
        headers = jwt.get_unverified_header(oauth_token)
        key_list = get_jwks_keys(oauth_provider_config.jwks_uri)
        signing_key = None
        for key in key_list:
            if key['kid'] == headers['kid']:
                signing_key = jwt.api_jwk.PyJWK(key)
                break

        if signing_key:
            try:
                # Decode token using signing key and audiences
                jwt_data = jwt.decode(
                    oauth_token,
                    signing_key.key,
                    algorithms=[oauth_provider_config.jwt_token_alg],
                    audience=audiences)
            except jwt.PyJWTError as e:
                raise AuthenticationException(f"Invalid token - {str(e)}")

            profile_identifiers = get_profile_identifiers(jwt_data, oauth_provider_config)

            # Lookup user via its profile identifiers (email or identity_id)
            for k, v in profile_identifiers.items():
                if v is not None:
                    # Get user from it's email
                    users = STORAGE.user.search(f"{k}:{v}", fl="*", as_obj=False, rows=1)['items']
                    if users:
                        # Limit user logging in from external token to only user READ/WRITE APIs
                        roles = load_roles_form_acls(["R", "W"], [])

                        if return_user:
                            return users[0], roles
                        return users[0]['uname'], roles
            msg = ", ".join([f"{k}={v}" for k, v in profile_identifiers.items() if v is not None])
            raise AuthenticationException(f"User not found - No matching user for the following identifiers ({msg})")


        raise AuthenticationException("Invalid token - No matching signing key found")

    return None, None
