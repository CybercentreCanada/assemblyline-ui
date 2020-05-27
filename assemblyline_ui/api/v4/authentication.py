
import hashlib
import pyqrcode
import re

from flask import request, session as flsk_session, current_app
from io import BytesIO
from passlib.hash import bcrypt

from assemblyline.common import forge
from assemblyline.common.comms import send_signup_email, send_reset_email
from assemblyline.common.isotime import now
from assemblyline.common.security import generate_random_secret, get_totp_token, \
    check_password_requirements, get_password_hash, get_password_requirement_message, get_random_password
from assemblyline_ui.api.base import make_api_response, api_login, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, config, KV_SESSION, get_signup_queue, get_reset_queue, LOGGER
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.security.authenticator import default_authenticator

Classification = forge.get_classification()
API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"]
}

SUB_API = 'auth'
auth_api = make_subapi_blueprint(SUB_API, api_version=4)
auth_api._doc = "Allow user to authenticate to the web server"


@auth_api.route("/apikey/<name>/<priv>/", methods=["GET"])
@api_login(audit=False)
def add_apikey(name, priv, **kwargs):
    """
    Add an API Key for the currently logged in user with given privileges

    Variables:
    name    => Name of the API key
    priv    => Requested privileges

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"apikey": <ramdomly_generated_password>}
    """
    user = kwargs['user']
    user_data = STORAGE.user.get(user['uname'])

    if name in user_data.apikeys:
        return make_api_response("", err=f"APIKey '{name}' already exist", status_code=400)

    if priv not in API_PRIV_MAP:
        return make_api_response("", err=f"Invalid APIKey privilege '{priv}'. Choose between: {API_PRIV_MAP.keys()}",
                                 status_code=400)

    random_pass = get_random_password(length=48)
    user_data.apikeys[name] = {"password": bcrypt.encrypt(random_pass), "acl": API_PRIV_MAP[priv]}
    STORAGE.user.save(user['uname'], user_data)

    return make_api_response({"apikey": f"{name}:{random_pass}"})


@auth_api.route("/apikey/<name>/", methods=["DELETE"])
@api_login(audit=False)
def delete_apikey(name, **kwargs):
    """
    Delete an API Key matching specified name for the currently logged in user

    Variables:
    name    => Name of the API key

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": True
    }
    """
    user = kwargs['user']
    user_data = STORAGE.user.get(user['uname'])
    user_data.apikeys.pop(name)
    STORAGE.user.save(user['uname'], user_data)

    return make_api_response({"success": True})


@auth_api.route("/disable_otp/", methods=["GET"])
@api_login(audit=False)
def disable_otp(**kwargs):
    """
    Disable OTP for the currently logged in user

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true
    }
    """
    uname = kwargs['user']['uname']
    user_data = STORAGE.user.get(uname)
    user_data.otp_sk = None
    user_data.security_tokens = {}
    STORAGE.user.save(uname, user_data)
    return make_api_response({"success": True})


@auth_api.route("/get_reset_link/", methods=["GET", "POST"])
def get_reset_link(**_):
    """
    Send a reset link via email to the email address specified

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "email": <EMAIL ADDRESS TO RESET PASSWORD>
    }

    Result example:
    {
     "success": true
    }
    """
    if not config.auth.internal.signup.enabled:
        return make_api_response({"success": False}, "Signup process has been disabled", 403)

    data = request.json
    if not data:
        data = request.values

    email = data.get('email', None)
    if email and STORAGE.user.search(f"email:{email}").get('total', 0) == 1:
        key = hashlib.sha256(get_random_password(length=512).encode('utf-8')).hexdigest()
        # noinspection PyBroadException
        try:
            send_reset_email(email, key)
            get_reset_queue(key).add(email)
            return make_api_response({"success": True})
        except Exception:
            make_api_response({"success": False}, "The system failed to send the password reset link.", 400)

    return make_api_response({"success": False}, "We have no record of this email address in our system.", 400)


# noinspection PyBroadException,PyPropertyAccess
@auth_api.route("/login/", methods=["GET", "POST"])
def login(**_):
    """
    Login the user onto the system
    
    Variables:
    None
    
    Arguments: 
    None
    
    Data Block:
    {
     "user": <UID>,
     "password": <ENCRYPTED_PASSWORD>,
     "otp": <OTP_TOKEN>,
     "apikey": <ENCRYPTED_APIKEY>,
     "webauthn_auth_resp": <RESPONSE_TO_CHALLENGE_FROM_WEBAUTHN>
    }

    Result example:
    {
     "username": <Logged in user>, # Username for the logged in user
     "privileges": ["R", "W"],     # Different privileges that the user will get for this session
     "session_duration": 60        # Time after which this session becomes invalid
                                   #   Note: The timer reset after each call
    }
    """
    data = request.json
    if not data:
        data = request.values

    user = data.get('user', None)
    password = data.get('password', None)
    apikey = data.get('apikey', None)
    webauthn_auth_resp = data.get('webauthn_auth_resp', None)
    oauth_provider = data.get('oauth_provider', None)
    oauth_token = data.get('oauth_token', None)

    if config.auth.oauth.enabled and oauth_provider:
        oauth = current_app.extensions.get('authlib.integrations.flask_client')
        provider = oauth.create_client(oauth_provider)

        if provider:
            redirect_uri = f'https://{request.host}/login.html?provider={oauth_provider}'
            return provider.authorize_redirect(redirect_uri=redirect_uri)

    try:
        otp = int(data.get('otp', 0) or 0)
    except Exception:
        raise AuthenticationException('Invalid OTP token')

    if (user and password) or (user and apikey) or (user and oauth_token):
        auth = {
            'username': user,
            'password': password,
            'otp': otp,
            'webauthn_auth_resp': webauthn_auth_resp,
            'apikey': apikey,
            'oauth_token': oauth_token
        }

        logged_in_uname = None
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        try:
            logged_in_uname, priv = default_authenticator(auth, request, flsk_session, STORAGE)
            session_duration = config.ui.session_duration
            cur_time = now()
            xsrf_token = generate_random_secret()
            current_session = {
                'duration': session_duration,
                'ip': ip,
                'privileges': priv,
                'time': int(cur_time) - (int(cur_time) % session_duration),
                'user_agent': request.headers.get("User-Agent", None),
                'username': logged_in_uname,
                'xsrf_token': xsrf_token
            }
            session_id = hashlib.sha512(str(current_session).encode("UTF-8")).hexdigest()
            current_session['expire_at'] = cur_time + session_duration
            flsk_session['session_id'] = session_id
            KV_SESSION.add(session_id, current_session)
            return make_api_response({
                "username": logged_in_uname,
                "privileges": priv,
                "session_duration": session_duration
            }, cookies={'XSRF-TOKEN': xsrf_token})
        except AuthenticationException as wpe:
            uname = auth.get('username', '(None)')
            LOGGER.warning(f"Authentication failure. (U:{uname} - IP:{ip}) [{wpe}]")
            return make_api_response("", err=str(wpe), status_code=401)
        finally:
            if logged_in_uname:
                LOGGER.info(f"Login successful. (U:{logged_in_uname} - IP:{ip})")

    return make_api_response("", "Not enough information to proceed with authentication", 401)


@auth_api.route("/logout/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'], check_xsrf_token=False)
def logout(**_):
    """
    Logout from the system clearing the current session

    Variables:
    None

    Arguments: 
    None

    Data Block:
    None

    Result example:
    {
     "success": true
    }
    """
    try:
        session_id = flsk_session.pop('session_id', None)
        KV_SESSION.pop(session_id)
        return make_api_response({"success": True})
    except ValueError:
        return make_api_response("", err="No user logged in?", status_code=400)


# noinspection PyBroadException
@auth_api.route("/reset_pwd/", methods=["GET", "POST"])
def reset_pwd(**_):
    """
    Reset the password for the specified reset ID

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "reset_id": <RESET_HASH>,
     "password": <PASSWORD TO RESET TO>,
     "password_confirm": <CONFIRMATION OF PASSWORD TO RESET TO>
    }

    Result example:
    {
     "success": true
    }
    """
    if not config.auth.internal.signup.enabled:
        return make_api_response({"success": False}, "Signup process has been disabled", 403)

    data = request.json
    if not data:
        data = request.values

    reset_id = data.get('reset_id', None)
    password = data.get('password', None)
    password_confirm = data.get('password_confirm', None)

    if reset_id and password and password_confirm:
        if password != password_confirm:
            return make_api_response({"success": False}, err="Password mismatch", status_code=400)

        password_requirements = config.auth.internal.password_requirements.as_primitives()
        if not check_password_requirements(password, **password_requirements):
            error_msg = get_password_requirement_message(**password_requirements)
            return make_api_response({"success": False}, error_msg, 469)

        try:
            reset_queue = get_reset_queue(reset_id)
            members = reset_queue.members()
            reset_queue.delete()
            if members:
                email = members[0]
                res = STORAGE.user.search(f"email:{email}")
                if res.get('total', 0) == 1:
                    user = STORAGE.user.get(res['items'][0].uname)
                    user.password = get_password_hash(password)
                    STORAGE.user.save(user.uname, user)
        except Exception:
            return make_api_response({"success": False}, err="Invalid parameters passed", status_code=400)

        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False}, err="Invalid parameters passed", status_code=400)


@auth_api.route("/setup_otp/", methods=["GET"])
@api_login(audit=False)
def setup_otp(**kwargs):
    """
    Setup OTP for the currently logged in user

    Variables:
    None

    Arguments: 
    None

    Data Block:
    None

    Result example:
    {
     "qrcode": <qrcode binary>,
     "otp_url": 'otpauth://totp/Assemblyline:{uname}?secret={secret_key}&issuer={site}',
     "secret_key": <SECRET KEY>
    }
    """
    uname = kwargs['user']['uname']

    user_data = STORAGE.user.get(uname)
    if user_data.otp_sk is not None:
        return make_api_response("", err="OTP already set for this user", status_code=400)

    secret_key = generate_random_secret()
    otp_url = 'otpauth://totp/{site}:{uname}?secret={secret_key}&issuer={site}'.format(uname=uname,
                                                                                       secret_key=secret_key,
                                                                                       site=config.ui.fqdn)
    qc_stream = BytesIO()
    temp_qrcode = pyqrcode.create(otp_url)
    temp_qrcode.svg(qc_stream, scale=3)

    flsk_session['temp_otp_sk'] = secret_key

    return make_api_response({
        'qrcode': qc_stream.getvalue().decode('utf-8'),
        'otp_url': otp_url,
        'secret_key': secret_key
    })


# noinspection PyBroadException,PyPropertyAccess
@auth_api.route("/signup/", methods=["GET", "POST"])
def signup(**_):
    """
    Signup a new user into the system

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "user": <UID>,
     "password": <DESIRED_PASSWORD>,
     "password_confirm": <DESIRED_PASSWORD_CONFIRMATION>,
     "email": <EMAIL_ADDRESS>
    }

    Result example:
    {
     "success": true
    }
    """
    if not config.auth.internal.signup.enabled:
        return make_api_response({"success": False}, "Signup process has been disabled", 403)

    data = request.json
    if not data:
        data = request.values

    uname = data.get('user', None)
    password = data.get('password', None)
    password_confirm = data.get('password_confirm', None)
    email = data.get('email', None)

    if not uname or not password or not password_confirm or not email:
        return make_api_response({"success": False}, "Not enough information to proceed with user creation", 400)

    if STORAGE.user.get(uname) or len(uname) < 3:
        return make_api_response({"success": False},
                                 "Invalid username. [Lowercase letters and dashes only with at least 3 letters]",
                                 460)
    else:
        for c in uname:
            if not 97 <= ord(c) <= 122 and not ord(c) == 45:
                return make_api_response({"success": False},
                                         "Invalid username. [Lowercase letters and dashes "
                                         "only with at least 3 letters]", 460)

    if password_confirm != password:
        return make_api_response("", "Passwords do not match", 469)

    password_requirements = config.auth.internal.password_requirements.as_primitives()
    if not check_password_requirements(password, **password_requirements):
        error_msg = get_password_requirement_message(**password_requirements)
        return make_api_response({"success": False}, error_msg, 469)

    if STORAGE.user.search(f"email:{email}").get('total', 0) != 0:
        return make_api_response({"success": False}, "Invalid email address", 466)

    email_valid = False
    for r in config.auth.internal.signup.valid_email_patterns:
        matcher = re.compile(r)
        if matcher.findall(email):
            email_valid = True
            break

    if not email_valid:
        extra = ""
        if config.ui.email:
            extra = f". Contact {config.ui.email} for more information."
        return make_api_response({"success": False}, f"Invalid email address{extra}", 466)

    password = get_password_hash(password)
    key = hashlib.sha256(get_random_password(length=512).encode('utf-8')).hexdigest()
    try:
        send_signup_email(email, key)
        get_signup_queue(key).add({
            "uname": uname,
            "password": password,
            "email": email,
            "groups": ['USERS'],
            "name": uname
        })
    except Exception:
        return make_api_response({"success": False}, "The system failed to send signup confirmation link.", 400)

    return make_api_response({"success": True})


@auth_api.route("/validate_otp/<token>/", methods=["GET"])
@api_login(audit=False)
def validate_otp(token, **kwargs):
    """
    Validate newly setup OTP token

    Variables:
    token     => Current token for temporary OTP sercret key

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true
    }
    """
    uname = kwargs['user']['uname']
    user_data = STORAGE.user.get(uname)

    try:
        token = int(token)
    except ValueError:
        return make_api_response({'success': False}, err="This is not a valid OTP token", status_code=400)

    secret_key = flsk_session.pop('temp_otp_sk', None)
    if secret_key and get_totp_token(secret_key) == token:
        user_data.otp_sk = secret_key
        STORAGE.user.save(uname, user_data)
        return make_api_response({'success': True})
    else:
        flsk_session['temp_otp_sk'] = secret_key
        return make_api_response({'success': False}, err="OTP token does not match secret key", status_code=400)
