import elasticapm

from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestedCredentialData, AuthenticatorData
from fido2.server import U2FFido2Server
from fido2.utils import websafe_decode
from fido2.webauthn import PublicKeyCredentialRpEntity

from assemblyline.common.security import get_totp_token
from assemblyline_ui.config import config
from assemblyline_ui.http_exceptions import AuthenticationException

rp = PublicKeyCredentialRpEntity(config.ui.fqdn, "Assemblyline server")
server = U2FFido2Server(f"https://{config.ui.fqdn}", rp)


@elasticapm.capture_span(span_type='authentication')
def validate_2fa(username, otp_token, state, webauthn_auth_resp, storage):
    security_token_enabled = False
    otp_enabled = False
    security_token_error = False
    otp_error = False
    report_errors = False

    # Get user
    user_data = storage.user.get(username)

    # Test Security Tokens
    if config.auth.allow_security_tokens:
        security_tokens = user_data.security_tokens

        credentials = [AttestedCredentialData(websafe_decode(x)) for x in security_tokens.values()]
        if credentials:
            # Security tokens are enabled for user
            security_token_enabled = True
            report_errors = True
            if state and webauthn_auth_resp:
                data = cbor.decode(bytes(webauthn_auth_resp))
                credential_id = data['credentialId']
                client_data = ClientData(data['clientDataJSON'])
                auth_data = AuthenticatorData(data['authenticatorData'])
                signature = data['signature']

                try:
                    server.authenticate_complete(state, credentials, credential_id, client_data, auth_data, signature)
                    return
                except Exception:
                    security_token_error = True

    # Test OTP
    if config.auth.allow_2fa:
        otp_sk = user_data.otp_sk
        if otp_sk:
            # OTP is enabled for user
            otp_enabled = True
            report_errors = True
            if otp_token:
                if get_totp_token(otp_sk) != otp_token:
                    otp_error = True
                else:
                    return

    if report_errors:
        if security_token_error:
            # Wrong response to challenge
            raise AuthenticationException("Wrong Security Token")
        elif otp_error:
            # Wrong token provided
            raise AuthenticationException("Wrong OTP token")
        elif security_token_enabled:
            # No challenge/response provided and security tokens are enabled
            raise AuthenticationException("Wrong Security Token")
        elif otp_enabled:
            # No OTP Token provided and OTP is enabled
            raise AuthenticationException("Wrong OTP token")

        # This should never hit
        raise AuthenticationException("Unknown 2FA Authentication error")
