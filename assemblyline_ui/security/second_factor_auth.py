from u2flib_server.u2f import complete_authentication

from assemblyline.common.security import get_totp_token
from assemblyline_ui.config import config, APP_ID
from assemblyline_ui.http_exceptions import AuthenticationException


# noinspection PyBroadException
def validate_2fa(username, otp_token, u2f_challenge, u2f_response, storage):
    u2f_enabled = False
    otp_enabled = False
    u2f_error = False
    otp_error = False
    report_errors = False

    # Get user
    user_data = storage.user.get(username)

    # Test u2f
    if config.auth.allow_u2f:
        u2f_devices = user_data.u2f_devices
        if isinstance(u2f_devices, list):
            u2f_devices = {"default": d for d in u2f_devices}

        registered_keys = u2f_devices.values()
        if registered_keys:
            # U2F is enabled for user
            u2f_enabled = True
            report_errors = True
            if u2f_challenge and u2f_response:
                try:
                    complete_authentication(u2f_challenge, u2f_response, [APP_ID])
                    return
                except Exception:
                    u2f_error = True

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
        if u2f_error:
            # Wrong response to challenge
            raise AuthenticationException("Wrong U2F Security Token")
        elif otp_error:
            # Wrong token provided
            raise AuthenticationException("Wrong OTP token")
        elif u2f_enabled:
            # No challenge/response provided and U2F is enabled
            raise AuthenticationException("Wrong U2F Security Token")
        elif otp_enabled:
            # No OTP Token provided and OTP is enabled
            raise AuthenticationException("Wrong OTP token")

        # This should never hit
        raise AuthenticationException("Unknown 2FA Authentication error")
