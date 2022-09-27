import jwt
import requests

from copy import copy

from assemblyline_ui.config import config, get_token_store, STORAGE
from assemblyline_ui.helper.oauth import parse_profile
from assemblyline_ui.http_exceptions import AuthenticationException


def validate_oauth_id(username, oauth_token_id):
    # This function identifies the user via a saved oauth_token_id in redis
    if config.auth.oauth.enabled and oauth_token_id:
        if get_token_store(username).exist(oauth_token_id):
            return username, ["R", "W", "E"]

        raise AuthenticationException("Invalid token")

    return None, None


def validate_oauth_token(oauth_token, oauth_provider):
    # This function identifies the user via an externally provided oauth token
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
        key_list = requests.get(oauth_provider_config.jwks_uri).json()["keys"]
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
                    algorithms=[headers['alg']],
                    audience=audiences)
            except jwt.PyJWTError as e:
                raise AuthenticationException(f"Invalid token - {str(e)}")

            # Get user's email from profile
            email = parse_profile(jwt_data, oauth_provider_config).get('email', None)
            if email is not None:
                # Get user from it's email
                users = STORAGE.user.search(f"email:{email}", fl="*", as_obj=False)['items']
                if users:
                    return users[0]['uname'], ["R", "W"]

        raise AuthenticationException("Invalid token")

    return None, None
