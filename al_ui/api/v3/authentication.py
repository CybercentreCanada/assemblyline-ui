
import base64
import hashlib
import pyqrcode
import re

from io import StringIO
from flask import request, session as flsk_session
from passlib.hash import bcrypt

from al_ui.config import STORAGE, config, KV_SESSION, get_signup_queue, get_reset_queue
from al_ui.http_exceptions import AuthenticationException
from al_ui.site_specific import default_authenticator
from assemblyline.common import forge
from al_ui.api.v3 import core
from al_ui.api.base import make_api_response, api_login
from assemblyline.common.auth_email import send_signup_email, send_reset_email
from assemblyline.common.security import generate_random_secret, load_async_key, get_totp_token, \
    check_password_requirements, get_password_hash, get_password_requirement_message, get_random_password
from assemblyline.common.isotime import now

SUB_API = 'auth'

Classification = forge.get_classification()

auth_api = core.make_subapi_blueprint(SUB_API)
auth_api._doc = "Allow user to authenticate to the web server"
API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"]
}


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
    user_data = STORAGE.get_user(user['uname'])

    if name in [x[0] for x in user_data.get('apikeys', [])]:
        return make_api_response("", err="APIKey %s already exist" % name, status_code=400)

    if priv not in API_PRIV_MAP.keys():
        return make_api_response("", err="Invalid APIKey privilege '%s'. "
                                         "Choose between: %s " % (priv, API_PRIV_MAP.keys()), status_code=400)

    keys = user_data.get('apikeys', [])
    random_pass = get_random_password(length=48)
    keys.append((name, bcrypt.encrypt(random_pass), API_PRIV_MAP[priv]))
    user_data['apikeys'] = keys
    STORAGE.save_user(user['uname'], user_data)

    return make_api_response({"apikey": random_pass})


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
    user_data = STORAGE.get_user(user['uname'])
    user_data['apikeys'] = [x for x in user_data.get('apikeys', []) if x[0] != name]
    STORAGE.save_user(user['uname'], user_data)

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
    user_data = STORAGE.get_user(uname)
    user_data.pop('otp_sk', None)
    STORAGE.save_user(uname, user_data)
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
    if not config.auth.internal.get('signup', {}).get('enabled', False):
        return make_api_response({"success": False}, "Signup process has been disabled", 403)

    data = request.json
    if not data:
        data = request.values

    email = data.get('email', None)
    if STORAGE.search_user("email:%s" % email).get('total', 0) == 1:
        key = hashlib.sha256(get_random_password(length=512)).hexdigest()
        send_reset_email(email, key)
        get_reset_queue(key).add(email)
    return make_api_response({"success": True})


# noinspection PyBroadException
@auth_api.route("/init/", methods=["GET"])
def init(**_):
    """
    Initialize secured handshake by downloading the server public
    key to encrypt the password

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    -----BEGIN PUBLIC KEY----- ....
    """
    if config.auth.get('encrypted_login', True):
        return make_api_response(STORAGE.get_blob('id_rsa.pub'))
    else:
        return make_api_response(None)


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
     "u2f_response": <RESPONSE_TO_CHALLENGE_FROM_U2F_TOKEN>
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
    u2f_response = data.get('u2f_response', None)

    if config.auth.get('encrypted_login', True):
        private_key = load_async_key(STORAGE.get_blob('id_rsa'), use_pkcs=True)

        if password and private_key:
            password = private_key.decrypt(base64.b64decode(password), "ERROR")

        if apikey and private_key:
            apikey = private_key.decrypt(base64.b64decode(apikey), "ERROR")

    try:
        otp = int(data.get('otp', 0) or 0)
    except Exception:
        raise AuthenticationException('Invalid OTP token')

    if request.environ.get("HTTP_X_REMOTE_CERT_VERIFIED", "FAILURE") == "SUCCESS":
        dn = request.environ.get("HTTP_X_REMOTE_DN")
    else:
        dn = False

    if (user and password) or dn or (user and apikey):
        auth = {
            'username': user,
            'password': password,
            'otp': otp,
            'u2f_response': u2f_response,
            'dn': dn,
            'apikey': apikey
        }

        try:
            logged_in_uname, priv = default_authenticator(auth, request, flsk_session, STORAGE)
            session_duration = config.ui.get('session_duration', 3600)
            cur_time = now()
            xsrf_token = generate_random_secret()
            current_session = {
                'duration': session_duration,
                'ip': request.headers.get("X-Forward-For", request.remote_addr),
                'privileges': priv,
                'time': int(cur_time) - (int(cur_time) % session_duration),
                'user_agent': request.headers.get("User-Agent", "Unknown user agent"),
                'username': logged_in_uname,
                'xsrf_token': xsrf_token
            }
            session_id = hashlib.sha512(str(current_session)).hexdigest()
            current_session['expire_at'] = cur_time + session_duration
            flsk_session['session_id'] = session_id
            KV_SESSION.add(session_id, current_session)
            return make_api_response({
                "username": logged_in_uname,
                "privileges": priv,
                "session_duration": config.ui.get('session_duration', 3600)
            }, cookies={'XSRF-TOKEN': xsrf_token})
        except AuthenticationException as wpe:
            return make_api_response("", wpe.message, 401)

    return make_api_response("", "Not enough information to proceed with authentication", 401)


@auth_api.route("/logout/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
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
    if not config.auth.internal.get('signup', {}).get('enabled', False):
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

        if not check_password_requirements(password, **config.auth.internal.get('password_requirements', {})):
            error_msg = get_password_requirement_message(**config.auth.internal.get('password_requirements', {}))
            return make_api_response({"success": False}, error_msg, 469)

        try:
            reset_queue = get_reset_queue(reset_id)
            members = reset_queue.members()
            reset_queue.delete()
            if members:
                email = members[0]
                res = STORAGE.search_user("email:%s" % email)
                if res.get('total', 0) == 1:
                    user = STORAGE.get_user(res['items'][0]['_yz_rk'])
                    user['password'] = get_password_hash(password)
                    STORAGE.save_user(user['uname'], user)
        except Exception:
            pass

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

    user_data = STORAGE.get_user(uname)
    if user_data.get("otp_sk", None):
        return make_api_response("", err="OTP already set for this user", status_code=400)

    secret_key = generate_random_secret()
    otp_url = 'otpauth://totp/{site}:{uname}?secret={secret_key}&issuer={site}'.format(uname=uname,
                                                                                       secret_key=secret_key,
                                                                                       site=config.ui.fqdn)
    qc_stream = StringIO()
    temp_qrcode = pyqrcode.create(otp_url)
    temp_qrcode.svg(qc_stream, scale=3)

    flsk_session['temp_otp_sk'] = secret_key

    return make_api_response({
        'qrcode': qc_stream.getvalue(),
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
    if not config.auth.internal.get('signup', {}).get('enabled', False):
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

    if STORAGE.get_user(uname) or len(uname) < 3:
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
    if not check_password_requirements(password, **config.auth.internal.get('password_requirements', {})):
        error_msg = get_password_requirement_message(**config.auth.internal.get('password_requirements', {}))
        return make_api_response({"success": False}, error_msg, 469)

    password = get_password_hash(password)

    if STORAGE.search_user("email:%s" % email).get('total', 0) != 0:
        return make_api_response({"success": False}, "Invalid email address", 466)

    email_valid = False
    for r in config.auth.internal.get('signup', {}).get('valid_email_patterns', []):
        matcher = re.compile(r)
        if matcher.findall(email):
            email_valid = True

    if not email_valid:
        return make_api_response({"success": False}, "Invalid email address", 466)

    key = hashlib.sha256(get_random_password(length=512)).hexdigest()
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
        pass

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
    user_data = STORAGE.get_user(uname)

    try:
        token = int(token)
    except ValueError:
        return make_api_response({'success': False}, err="This is not a valid OTP token", status_code=400)

    secret_key = flsk_session.pop('temp_otp_sk', None)
    if get_totp_token(secret_key) == token:
        user_data['otp_sk'] = secret_key
        STORAGE.save_user(uname, user_data)
        return make_api_response({'success': True})
    else:
        flsk_session['temp_otp_sk'] = secret_key
        return make_api_response({'success': False}, err="OTP token does not match secret key", status_code=400)
