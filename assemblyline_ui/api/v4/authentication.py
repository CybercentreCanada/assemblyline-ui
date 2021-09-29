
import hashlib
import jwt
import pyqrcode
import re

from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.base_client import OAuthError
from flask import current_app, redirect, request
from flask import session as flsk_session
from io import BytesIO
from passlib.hash import bcrypt
from urllib.parse import urlparse

from assemblyline.common import forge
from assemblyline.common.comms import send_reset_email, send_signup_email
from assemblyline.common.isotime import now
from assemblyline.common.security import (check_password_requirements, generate_random_secret, get_password_hash,
                                          get_password_requirement_message, get_random_password, get_totp_token)
from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.user import User
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import (KV_SESSION, LOGGER, SECRET_KEY, STORAGE, config, get_reset_queue,
                                    get_signup_queue, get_token_store)
from assemblyline_ui.helper.oauth import fetch_avatar, parse_profile
from assemblyline_ui.helper.user import get_dynamic_classification
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.security.authenticator import default_authenticator

Classification = forge.get_classification()
API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"]
}

if config.auth.allow_extended_apikeys:
    API_PRIV_MAP["EXTENDED"] = ["R", "W", "E"]

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


@auth_api.route("/obo_token/<token_id>/", methods=["DELETE"])
@api_login(audit=False)
def delete_obo_token(token_id, **kwargs):
    """
    Delete an application access to your profile

    Variables:
    None

    Arguments:
    token_id     =>   ID of the application token to delete

    Data Block:
    None

    Result example:
    {'success': true}
    """

    uname = kwargs['user']['uname']
    user_data = STORAGE.user.get(uname, as_obj=False)
    if token_id not in user_data.get('apps', {}):
        return make_api_response({"success": False}, "Token ID does not exist", 404)

    user_data['apps'].pop(token_id)
    STORAGE.user.save(uname, user_data)
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


@auth_api.route("/obo_token/", methods=["GET"])
@api_login(audit=False)
def get_obo_token(**kwargs):
    """
    Get or create a token to allow an external application to impersonate your
    user account while querying Assemblyline's API.

    Variables:
    None

    Arguments:
    client_id     =>   User account of the application that will be allowed to use the token
    redirect_url  =>   URL that AL will send to token to
    scope         =>   Authorization scope (either r, w or rw)
    server        =>   Name of the server requesting access

    Data Block:
    None

    Result example:
    <A JWT TOKEN>
    """
    if request.referrer is None or request.host not in request.referrer:
        return make_api_response({"success": False}, "Forbidden", 403)

    params = request.values
    client_id = params.get('client_id', None)
    redirect_url = params.get('redirect_url', None)
    scope = params.get('scope', None)
    server = params.get('server', None)

    if not redirect_url:
        return make_api_response({"success": False}, "redirect_url missing", 400)

    parsed_url = urlparse(redirect_url)
    if parsed_url.scheme != 'https':
        return make_api_response({"success": False}, "Insecure redirect-url, ignored...", 400)

    if parsed_url.query:
        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{parsed_url.query}&"
    else:
        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"

    if not client_id or not scope or not server:
        err_type = "missing_arguments"
        err_description = "client_id, scope and server are required arguments"
        return redirect(f"{redirect_url}error={err_type}&error_description={err_description}")

    uname = kwargs['user']['uname']
    user_data = STORAGE.user.get(uname, as_obj=False)

    token_data = {'client_id': client_id, 'scope': scope, 'netloc': parsed_url.netloc, 'server': server}
    token_id = None
    for k, v in user_data.get('apps', {}).items():
        if v == token_data:
            token_id = k
            break

    if not token_id:
        user_data.setdefault('apps', {})
        token_id = get_random_id()
        user_data['apps'][token_id] = token_data
        STORAGE.user.save(uname, user_data)

    token = jwt.encode(token_data, hashlib.sha256(f"{SECRET_KEY}_{token_id}".encode()).hexdigest(),
                       algorithm="HS256", headers={'token_id': token_id, 'user': uname})
    return redirect(f"{redirect_url}token={token}")


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
    if email and STORAGE.user.search(f"email:{email.lower()}").get('total', 0) == 1:
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
            redirect_uri = f'https://{request.host}/oauth/{oauth_provider}/'
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

            # Cleanup expired sessions
            for k, v in KV_SESSION.items().items():
                expire_at = v.get('expire_at', 0)
                if expire_at < cur_time:
                    KV_SESSION.pop(k)
                    LOGGER.info(f"The following session ID was removed because of a timeout. "
                                f"[User: {v.get('username', 'unknown')}, SessionID: {k[:16]}...]")

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
        session_id = flsk_session.get('session_id', None)
        if session_id:
            KV_SESSION.pop(session_id)
        flsk_session.clear()
        res = make_api_response({"success": True})
        res.set_cookie('XSRF-TOKEN', '', max_age=0)
        return res
    except ValueError:
        return make_api_response("", err="No user logged in?", status_code=400)


# noinspection PyBroadException
@auth_api.route("/oauth/", methods=["GET"])
def oauth_validate(**_):
    """
    Validate and oAuth session and return it's associated username, avatar and oAuth Token

    Variables:
    None

    Arguments:
    provider   =>   Which oAuth provider to validate the token against
    *          =>   All parameters returned by your oAuth provider callback...

    Data Block:
    None

    Result example:
    {
     "avatar": "data:image...",
     "oauth_token": "123123...123213",
     "username": "user"
    }
    """
    oauth_provider = request.values.get('provider', None)
    avatar = None
    username = None
    email_adr = None
    oauth_token = None

    if config.auth.oauth.enabled:
        oauth = current_app.extensions.get('authlib.integrations.flask_client')
        provider = oauth.create_client(oauth_provider)

        if provider:
            # noinspection PyBroadException
            try:
                oauth_provider_config = config.auth.oauth.providers[oauth_provider]
                if oauth_provider_config.app_provider:
                    # Validate the token that we've received using the secret
                    token = provider.authorize_access_token(client_secret=oauth_provider_config.client_secret)

                    # Initialize the app_provider
                    app_provider = OAuth2Session(
                        oauth_provider_config.app_provider.client_id or oauth_provider_config.client_id,
                        oauth_provider_config.app_provider.client_secret or oauth_provider_config.client_secret,
                        scope=oauth_provider_config.app_provider.scope)
                    app_provider.fetch_token(
                        oauth_provider_config.app_provider.access_token_url,
                        grant_type="client_credentials")

                else:
                    # Validate the token
                    token = provider.authorize_access_token()
                    app_provider = None

                user_data = None
                if oauth_provider_config.jwks_uri:
                    user_data = provider.parse_id_token(token)

                # Get user data from endpoint
                if app_provider and oauth_provider_config.app_provider.user_get:
                    url = oauth_provider_config.app_provider.user_get
                    uid = user_data.get('id', None)
                    if not uid and user_data and oauth_provider_config.uid_field:
                        uid = user_data.get(oauth_provider_config.uid_field, None)
                    if uid:
                        url = url.format(id=uid)
                    resp = app_provider.get(url)
                    if resp.ok:
                        user_data = resp.json()
                elif not user_data:
                    resp = provider.get(oauth_provider_config.user_get)
                    if resp.ok:
                        user_data = resp.json()

                # Add group data if API is configured for it
                groups = []
                if app_provider and oauth_provider_config.app_provider.group_get:
                    url = oauth_provider_config.app_provider.group_get
                    uid = user_data.get('id', None)
                    if not uid and user_data and oauth_provider_config.uid_field:
                        uid = user_data.get(oauth_provider_config.uid_field, None)
                    if uid:
                        url = url.format(id=uid)
                    resp_grp = app_provider.get(url)
                    if resp_grp.ok:
                        groups = resp_grp.json()
                elif oauth_provider_config.user_groups:
                    resp_grp = provider.get(oauth_provider_config.user_groups)
                    if resp_grp.ok:
                        groups = resp_grp.json()

                if groups:
                    if oauth_provider_config.user_groups_data_field:
                        groups = groups[oauth_provider_config.user_groups_data_field]

                    if oauth_provider_config.user_groups_name_field:
                        groups = [x[oauth_provider_config.user_groups_name_field] for x in groups]

                    user_data['groups'] = groups

                if user_data:
                    data = parse_profile(user_data, oauth_provider_config)
                    has_access = data.pop('access', False)
                    if has_access and data['email'] is not None:
                        oauth_avatar = data.pop('avatar', None)

                        # Find if user already exists
                        users = STORAGE.user.search(f"email:{data['email']}", fl="uname", as_obj=False)['items']
                        if users:
                            cur_user = STORAGE.user.get(users[0]['uname'], as_obj=False) or {}
                            # Do not update username and password from the current user
                            data['uname'] = cur_user.get('uname', data['uname'])
                            data['password'] = cur_user.get('password', data['password'])
                        else:
                            if data['uname'] != data['email']:
                                # Username was computed using a regular expression, lets make sure we don't
                                # assign the same username to two users
                                res = STORAGE.user.search(f"uname:{data['uname']}", rows=0, as_obj=False)
                                if res['total'] > 0:
                                    cnt = res['total']
                                    new_uname = f"{data['uname']}{cnt}"
                                    while STORAGE.user.get(new_uname) is not None:
                                        cnt += 1
                                        new_uname = f"{data['uname']}{cnt}"
                                    data['uname'] = new_uname
                            cur_user = {}

                        username = data['uname']
                        email_adr = data['email']

                        # Add add dynamic classification group
                        data['classification'] = get_dynamic_classification(data['classification'], data['email'])

                        # Make sure the user exists in AL and is in sync
                        if (not cur_user and oauth_provider_config.auto_create) or \
                                (cur_user and oauth_provider_config.auto_sync):

                            # Update the current user
                            cur_user.update(data)

                            # Save avatar
                            if oauth_avatar:
                                avatar = fetch_avatar(oauth_avatar, provider, oauth_provider_config)
                                if avatar:
                                    STORAGE.user_avatar.save(username, avatar)

                            # Save updated user
                            STORAGE.user.save(username, cur_user)

                        if cur_user:
                            if avatar is None:
                                avatar = STORAGE.user_avatar.get(username) or "/static/images/user_default.png"
                            oauth_token = hashlib.sha256(str(token).encode("utf-8", errors='replace')).hexdigest()
                            get_token_store(username).add(oauth_token)
                        else:
                            return make_api_response({"err_code": 3},
                                                     err="User auto-creation is disabled",
                                                     status_code=403)
                    else:
                        return make_api_response({"err_code": 2}, err="This user is not allowed access to the system",
                                                 status_code=403)

            except OAuthError as err:
                return make_api_response({"err_code": 1}, err=str(err), status_code=401)

            except Exception as err:
                LOGGER.exception(str(err))
                return make_api_response({"err_code": 1, "exception": str(err)},
                                         err="Unhandled exception occured while processing oAuth token",
                                         status_code=401)

    if username is None:
        return make_api_response({"err_code": 0}, err="oAuth disabled on the server", status_code=401)

    return make_api_response({
        "avatar": avatar,
        "username": username,
        "oauth_token": oauth_token,
        "email_adr": email_adr
    })


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
            return make_api_response({"success": False}, err="Password mismatch", status_code=469)

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
                    return make_api_response({"success": True})

        except Exception as e:
            LOGGER.warning(f"Failed to reset the user's password: {str(e)}")
            pass

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
                                 "There is already a user registered with this name",
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

    if STORAGE.user.search(f"email:{email.lower()}").get('total', 0) != 0:
        return make_api_response({"success": False}, "There is already a user registered with this email address", 466)

    # Normalize email address
    email = email.lower()
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
    except Exception as e:
        LOGGER.warning(f"Sending email for signup process failed: {str(e)}")
        return make_api_response({"success": False}, "The system failed to send signup confirmation link.", 400)

    return make_api_response({"success": True})


# noinspection PyBroadException,PyPropertyAccess
@auth_api.route("/signup_validate/", methods=["POST"])
def signup_validate(**_):
    """
    Validate a user's signup request

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
     "registration_key": "234234...ADFCB"    # Key used to validate the user's signup process
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

    registration_key = data.get('registration_key', None)

    if registration_key:
        try:
            signup_queue = get_signup_queue(registration_key)
            members = signup_queue.members()
            signup_queue.delete()
            if members:
                user_info = members[0]

                # Add dynamic classification group
                user_info['classification'] = get_dynamic_classification(
                    user_info.get('classification', Classification.UNRESTRICTED), user_info['email'])

                user = User(user_info)
                username = user.uname

                STORAGE.user.save(username, user)
                return make_api_response({"success": True})
        except (KeyError, ValueError) as e:
            LOGGER.warning(f"Fail to signup user: {str(e)}")
            pass
    else:
        return make_api_response({"success": False}, "Not enough information to proceed with user creation", 400)

    return make_api_response({"success": False}, "Invalid registration key", 400)


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
