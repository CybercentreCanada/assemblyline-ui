import base64
import hashlib
import json
import re
from io import BytesIO
from typing import Any, Dict
from urllib.parse import urlparse

import jwt
import pyqrcode
from datetime import datetime, timezone
from assemblyline.common.comms import send_reset_email, send_signup_email
from assemblyline.common.isotime import now
from assemblyline.common.security import (
    check_password_requirements,
    generate_random_secret,
    get_password_hash,
    get_password_requirement_message,
    get_random_password,
    get_totp_token,
)
from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.user import ROLES, User, load_roles, load_roles_form_acls
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.config import (
    KV_SESSION,
    LOGGER,
    SECRET_KEY,
    STORAGE,
    config,
    get_reset_queue,
    get_signup_queue,
    get_token_store,
)
from assemblyline_ui.helper.oauth import fetch_avatar, parse_profile
from assemblyline_ui.helper.user import API_PRIV_MAP, get_default_user_quotas, get_dynamic_classification
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.security.authenticator import default_authenticator
from assemblyline_ui.security.saml_auth import get_attribute, get_roles, get_types
from authlib.integrations.base_client import OAuthError
from authlib.integrations.requests_client import OAuth2Session
from authlib.integrations.flask_client import OAuth
from azure.identity import DefaultAzureCredential
from flask import current_app, redirect, request
from flask import session as flsk_session
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from werkzeug.exceptions import BadRequest, UnsupportedMediaType

GRAPH_API_ENDPOINT = 'https://graph.microsoft.com/v1.0'

SCOPES = {
    'r': ["R"],
    'w': ["W"],
    'rw': ["R", "W"],
    'c': ["C"]
}

SUB_API = 'auth'
auth_api = make_subapi_blueprint(SUB_API, api_version=4)
auth_api._doc = "Allow user to authenticate to the web server"


@auth_api.route("/apikey/<name>/<priv>/", methods=["PUT"])
@api_login(audit=False, require_role=[ROLES.apikey_access], count_toward_quota=False)
def add_apikey(name, priv, **kwargs):
    """
    Add an API Key for the currently logged in user with given privileges

    Variables:
    name    => Name of the API key
    priv    => Requested privileges

    Arguments:
    None

    Data Block:
    ['submission_view', 'file_detail']  # List of roles if priv is CUSTOM

    Result example:
    {"apikey": <ramdomly_generated_password>}
    """
    user = kwargs['user']
    user_data = STORAGE.user.get(user['uname'], as_obj=False)

    if name in user_data['apikeys']:
        return make_api_response("", err=f"APIKey '{name}' already exist", status_code=400)

    if priv not in API_PRIV_MAP:
        return make_api_response("", err=f"Invalid APIKey privilege '{priv}'. Choose between: {API_PRIV_MAP.keys()}",
                                 status_code=400)

    if priv == "CUSTOM":
        try:
            roles = request.json
        except BadRequest:
            return make_api_response("", err="Invalid data block provided. Provide a list of roles as JSON.",
                                     status_code=400)
    else:
        roles = None

    random_pass = get_random_password(length=48)
    priv_map = API_PRIV_MAP[priv]
    roles = [r for r in load_roles_form_acls(priv_map, roles)
             if r in load_roles(user_data['type'], user_data.get('roles', None))]

    if not roles:
        return make_api_response(
            "", err="None of the roles you've requested for this key are allowed for this user.", status_code=400)

    user_data['apikeys'][name] = {
        "password": get_password_hash(random_pass),
        "acl": priv_map,
        "roles": roles
    }
    STORAGE.user.save(user['uname'], user_data)

    return make_api_response({"acl": priv_map, "apikey": f"{name}:{random_pass}", "name": name,  "roles": roles})


@auth_api.route("/apikey/<name>/", methods=["DELETE"])
@api_login(audit=False, require_role=[ROLES.apikey_access], count_toward_quota=False)
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
    user_data = STORAGE.user.get(user['uname'], as_obj=False)
    user_data['apikeys'].pop(name)
    STORAGE.user.save(user['uname'], user_data)

    return make_api_response({"success": True})


@auth_api.route("/obo_token/<token_id>/", methods=["DELETE"])
@api_login(audit=False, require_role=[ROLES.obo_access], count_toward_quota=False)
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
@api_login(audit=False, require_role=[ROLES.self_manage], count_toward_quota=False)
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
    user_data = STORAGE.user.get(uname, as_obj=False)
    user_data['otp_sk'] = None
    user_data['security_tokens'] = {}
    STORAGE.user.save(uname, user_data)
    return make_api_response({"success": True})


@auth_api.route("/obo_token/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.obo_access], count_toward_quota=False)
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
    roles = params.get('roles', None)
    server = params.get('server', None)

    if not redirect_url:
        return make_api_response({"success": False}, "Redirect_url missing", 400)

    if roles:
        scope = 'c'
        roles = roles.split(",")
    else:
        if scope not in SCOPES:
            return make_api_response({"success": False}, "Invalid Scope selected", 400)

    # Load roles from ACL if needed and validate them
    roles = [r for r in load_roles_form_acls(SCOPES[scope], roles)
             if ROLES.contains_value(r)]

    parsed_url = urlparse(redirect_url)
    if parsed_url.scheme != 'https':
        return make_api_response({"success": False}, "Insecure redirect-url, ignored...", 400)

    if parsed_url.query:
        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{parsed_url.query}&"
    else:
        redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?"

    if not client_id or not roles or not server:
        err_type = "missing_arguments"
        err_description = \
            "client_id, roles and server are required arguments. You can also use scope to define a set of roles."
        return redirect(f"{redirect_url}error={err_type}&error_description={err_description}")

    uname = kwargs['user']['uname']
    user_data = STORAGE.user.get(uname, as_obj=False)

    token_data = {
        'client_id': client_id,
        'scope': scope,
        'netloc': parsed_url.netloc,
        'server': server,
        'roles': roles}
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

    try:
        data = request.json
    except (BadRequest, UnsupportedMediaType):
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
     "webauthn_auth_resp": <RESPONSE_TO_CHALLENGE_FROM_WEBAUTHN>,
     "oauth_token_id": <ID OF THE OAUTH TOKEN>,
     "oauth_token": <JWT TOKEN TO USE FOR AUTHENTICATION>
     "saml_token_id": <ID OF THE SAML TOKEN>
    }

    Result example:
    {
     "username": <Logged in user>, # Username for the logged in user
     "privileges": ["R", "W"],     # Different privileges that the user will get for this session
     "session_duration": 60        # Time after which this session becomes invalid
                                   #   Note: The timer reset after each call
    }
    """
    try:
        data = request.json
    except (BadRequest, UnsupportedMediaType):
        data = request.values

    user = data.get('user', None)
    password = data.get('password', None)
    apikey = data.get('apikey', None)
    webauthn_auth_resp = data.get('webauthn_auth_resp', None)
    oauth_provider = data.get('oauth_provider', None)
    oauth_token_id = data.get('oauth_token_id', None)
    oauth_token = data.get('oauth_token', None)
    saml_token_id = data.get('saml_token_id', None)

    if config.auth.oauth.enabled and oauth_provider and oauth_token is None:
        oauth = current_app.extensions.get('authlib.integrations.flask_client')
        provider = oauth.create_client(oauth_provider)

        redirect_uri = config.auth.oauth.providers.get(oauth_provider).redirect_uri
        if provider:
            redirect_uri = redirect_uri or f'https://{request.host}/oauth/{oauth_provider}/'
            return provider.authorize_redirect(redirect_uri=redirect_uri)

    try:
        otp = int(data.get('otp', 0) or 0)
    except Exception:
        raise AuthenticationException('Invalid OTP token')

    if (user and password) or \
       (user and apikey) or \
       (user and oauth_token_id) or \
        oauth_token or \
       (user and saml_token_id):
        auth = {
            'username': user,
            'password': password,
            'otp': otp,
            'webauthn_auth_resp': webauthn_auth_resp,
            'apikey': apikey,
            'oauth_token_id': oauth_token_id,
            'oauth_token': oauth_token,
            'oauth_provider': oauth_provider,
            'saml_token_id': saml_token_id
        }

        logged_in_uname = None
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        try:
            logged_in_uname, roles_limit = default_authenticator(auth, request, flsk_session, STORAGE)
            session_duration = config.ui.session_duration
            cur_time = now()
            xsrf_token = generate_random_secret()
            current_session = {
                'duration': session_duration,
                'ip': ip,
                'roles_limit': roles_limit,
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
                "roles_limit": roles_limit,
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
@api_login(audit=False, check_xsrf_token=False, count_toward_quota=False)
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


@auth_api.route("/saml/sso/", methods=["GET"])
def saml_sso(**_):
    """
    SAML Single Sign-On method, sets up SSO and redirect the user to the SAML server

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <REDIRECT TO SAML AUTH SERVER>
    """
    if not config.auth.saml.enabled:
        return make_api_response({"err_code": 0}, err="SAML disabled on the server", status_code=401)
    auth: OneLogin_Saml2_Auth = _make_saml_auth()
    host: str = config.ui.fqdn or request.host
    path: str = urlparse(request.referrer).path
    if isinstance(path, bytes):
        path = path.decode('utf-8')
    sso_built_url: str = auth.login(return_to=f"https://{host}{path}")
    flsk_session["AuthNRequestID"] = auth.get_last_request_id()
    return redirect(sso_built_url)


@auth_api.route("/saml/acs/", methods=["GET", "POST"])
def saml_acs(**_):
    '''
    SAML Assertion Consumer Service (ACS). This is the endpoint the SAML server will redirect to
    with the authentication token. This endpoint will validate the token and create or link to
    the associated user. And will then redirect the user to the login page.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <REDIRECT TO AL's LOGIN PAGE>
    '''
    if not config.auth.saml.enabled:
        return make_api_response({"err_code": 0}, err="SAML disabled on the server", status_code=401)
    request_data: Dict[str, Any] = _prepare_flask_request(request)
    auth: OneLogin_Saml2_Auth = _make_saml_auth(request_data)
    request_id: str = flsk_session.pop("AuthNRequestID", None)

    if not request_id:
        # Could not found the request ID, this token was already used, redirect to the UI with the error
        msg = "Invalid SAML token"
        data = base64.b64encode(json.dumps({'error': msg}).encode('utf-8')).decode()
        return redirect(f"https://{config.ui.fqdn}/saml/?data={data}")

    auth.process_response(request_id=request_id)
    errors: list = auth.get_errors()

    # If authentication failed, it'll be noted in `errors`
    if len(errors) == 0:
        # if the 'User' type is defined in the group_type_mapping
        # limit access to group members, else allow all athenticated users
        valid_groups = config.auth.saml.attributes.group_type_mapping
        if 'user' in (value.lower() for value in valid_groups.values()):
            user_groups = auth.get_attribute(config.auth.saml.attributes.groups_attribute) or []
            if not any(group in valid_groups for group in user_groups):
                error_message = (f"User was not in one of the required groups: {valid_groups.keys()}. "
                                 f"User's groups: {user_groups}")
                return make_api_response({"err_code": 1}, err=error_message, status_code=401)

        # Validate or create the user right away
        saml_user_data = auth.get_attributes()
        username = get_attribute(saml_user_data, config.auth.saml.attributes.username_attribute) or auth.get_nameid()

        # Get user if exists
        cur_user = STORAGE.user.get(username, as_obj=False) or {}

        # Make sure the user exists in AL and is in sync
        if (not cur_user and config.auth.saml.auto_create) or (cur_user and config.auth.saml.auto_sync):
            # Generate user data from SAML
            email: Any = get_attribute(saml_user_data, config.auth.saml.attributes.email_attribute)
            if email is not None:
                email = email.lower()
            name = get_attribute(saml_user_data, config.auth.saml.attributes.fullname_attribute) or username

            data = dict(
                uname=username,
                name=name,
                email=email,
                password="__NO_PASSWORD__"
            )

            # Get the user type from the SAML data
            data['type'] = get_types(saml_user_data) or ['user']

            # Load in user roles or get the roles from the types
            user_roles = get_roles(saml_user_data) or None
            data['roles'] = load_roles(data['type'], user_roles)

            # Load in the user DN
            if (dn := get_attribute(saml_user_data, "dn")):
                data['dn'] = dn

            # Get the dynamic classification info
            if (u_classification := get_attribute(saml_user_data, 'classification')):
                data["classification"] = get_dynamic_classification(u_classification, data)

            # Save the updated user
            cur_user.update(data)
            STORAGE.user.save(username, cur_user)

        else:
            # User does not exists and auto_create is OFF, redirect to the UI with the error
            msg = "User does not exists"
            data = base64.b64encode(json.dumps({'error': msg}).encode('utf-8')).decode()
            return redirect(f"https://{config.ui.fqdn}/saml/?data={data}")

        # Generating the Token the UI will use to login
        saml_token_id = hashlib.sha256(request_id.encode("utf-8", errors='replace')).hexdigest()

        if get_token_store(username, 'saml').exist(saml_token_id):
            # Token already exists, this may be a replay attack, redirect to the UI with the error
            msg = "Invalid SAML token"
            data = base64.b64encode(json.dumps({'error': msg}).encode('utf-8')).decode()
            return redirect(f"https://{config.ui.fqdn}/saml/?data={data}")

        # Saving the ID of the valid session our token store
        get_token_store(username, 'saml').add(saml_token_id)

        # Create the data blob to send to the UI
        data = {
            'username': username,
            'email': cur_user['email'],
            'saml_token_id': saml_token_id
        }
        data = base64.b64encode(json.dumps(data).encode('utf-8')).decode()

        # Redirect to the UI with the response
        return redirect(f"https://{config.ui.fqdn}/saml/?data={data}")
    else:
        # The user could not be validated properly, redirect to the UI with the errors
        errors = "\n".join([f" - {error}\n" for error in auth.get_errors()])
        LOGGER.error(f"SAML ACS request failed: {auth.get_last_error_reason()}\n{errors}")
        data = base64.b64encode(json.dumps({'error': errors}).encode('utf-8')).decode()
        return redirect(f"https://{config.ui.fqdn}/saml/?data={data}")

def create_token_dict(access_token_obj):
    """
    Process the AccessToken object to create a dictionary suitable for OAuth2Session.

    :param access_token_obj: The AccessToken object returned from `get_fic_access_token`.
    :return: A dictionary with token details.
    """
    token = access_token_obj.token
    expires_on = access_token_obj.expires_on

    # Calculate the expiration time from the current time and the 'expires_on' timestamp
    expires_in = expires_on - int(datetime.now(timezone.utc).timestamp())

    return {
        'access_token': token,
        'token_type': 'Bearer',
        'expires_in': expires_in,
        'expires_at': expires_on
    }

def get_fic_access_token(client_id, tenant_id, scope):
    try:
        credential = DefaultAzureCredential(
            workload_identity_client_id=client_id, workload_identity_tenant_id=tenant_id)
        token = credential.get_token(scope)
    except Exception as e:
        error_msg = f"Failed to retrieve federated token: {str(e)}"
        raise Exception(error_msg)

    return token

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
        "oauth_token_id": "123123...123213",
        "username": "user"
    }
    """
    oauth_provider = request.values.get('provider', None)
    avatar = None
    username = None
    email_adr = None
    app_provider = None
    oauth_token_id = None

    # Current user data
    user_data = {}
    # Current user groups
    groups = []

    if config.auth.oauth.enabled:
        oauth: OAuth = current_app.extensions.get('authlib.integrations.flask_client')
        provider = oauth.create_client(oauth_provider)

        if provider:
            # noinspection PyBroadException
            try:
                # Load the oAuth provider config
                oauth_provider_config = config.auth.oauth.providers[oauth_provider]

                # Federated Identity Credentials
                use_fic = oauth_provider_config.use_federated_credentials

                if use_fic:
                    # Use DefaultAzureCredential to get a federated token
                    tenant_id = oauth_provider_config.tenant_id
                    client_id = oauth_provider_config.client_id
                    scope = oauth_provider_config.federated_credential_scope

                    try:
                        fic_token = get_fic_access_token(client_id=client_id, tenant_id=tenant_id, scope=scope)
                        token_dict = create_token_dict(fic_token)
                        token = provider.token = token_dict
                    except Exception as e:
                        return make_api_response({"err_code": 3}, err=f"Unable to authenticate using Federated Credentials: {e}", status_code=500)

                # Validate the token in non fic workflows
                if use_fic:
                    token = fic_token
                elif oauth_provider_config.validate_token_with_secret or oauth_provider_config.app_provider:
                    # Validate the token that we've received using the secret
                    token = provider.authorize_access_token(client_secret=oauth_provider_config.client_secret)
                else:
                    token = provider.authorize_access_token()

                # Setup alternate app provider if we need to fetch groups of user info by hand
                # Initialize the app_provider
                if oauth_provider_config.app_provider and (
                        oauth_provider_config.app_provider.user_get or oauth_provider_config.app_provider.group_get):
                    app_provider = OAuth2Session(
                        oauth_provider_config.app_provider.client_id or oauth_provider_config.client_id,
                        oauth_provider_config.app_provider.client_secret or oauth_provider_config.client_secret,
                        scope=oauth_provider_config.app_provider.scope)
                    app_provider.fetch_token(
                        oauth_provider_config.app_provider.access_token_url,
                        grant_type="client_credentials")

                # Add user_data info from received token
                if oauth_provider_config.jwks_uri:
                    user_data = provider.parse_id_token(token)

                # Add user data from app_provider endpoint
                if app_provider and oauth_provider_config.app_provider.user_get:
                    url = oauth_provider_config.app_provider.user_get
                    uid = user_data.get('id', None)

                    if not uid and user_data and oauth_provider_config.uid_field:
                        uid = user_data.get(oauth_provider_config.uid_field, None)

                    if uid:
                        url = url.format(id=uid)

                    resp = app_provider.get(url)
                    if resp.ok:
                        user_data.update(resp.json())

                # Add user data from user_get endpoint
                elif oauth_provider_config.user_get:
                    resp = provider.get(oauth_provider_config.user_get)
                    if resp.ok:
                        user_data.update(resp.json())

                # Add group data from app_provider endpoint
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

                # Add group data from group_get endpoint
                elif oauth_provider_config.user_groups:
                    resp_grp = provider.get(oauth_provider_config.user_groups)
                    if resp_grp.ok:
                        groups = resp_grp.json()

                # Parse received groups
                if groups:
                    if oauth_provider_config.user_groups_data_field:
                        groups = groups[oauth_provider_config.user_groups_data_field]

                    if oauth_provider_config.user_groups_name_field:
                        groups = [x[oauth_provider_config.user_groups_name_field] for x in groups]

                    user_data['groups'] = groups

                if user_data:
                    data = parse_profile(user_data, oauth_provider_config)
                    has_access = data.pop('access', False)

                    if data['email'] is None:
                        return make_api_response({"err_code": 4}, err="Could not find an email address for the user",
                                                    status_code=403)

                    if not has_access:
                        return make_api_response({"err_code": 2}, err="This user is not allowed access to the system",
                                                    status_code=403)

                    # Find if user already exists
                    users = STORAGE.user.search(f"email:{data['email']}", fl="*", as_obj=False)['items']
                    if users:
                        cur_user = users[0]
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
                                while STORAGE.user.exists(new_uname):
                                    cnt += 1
                                    new_uname = f"{data['uname']}{cnt}"
                                data['uname'] = new_uname
                        cur_user = {}

                    username = data['uname']
                    email_adr = data['email']

                    # Add add dynamic classification group
                    data['classification'] = get_dynamic_classification(data['classification'], data)

                    oauth_avatar = data.pop('avatar', None)

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
                        STORAGE.user.save(username, get_default_user_quotas(cur_user))

                    if cur_user:
                        if avatar is None:
                            avatar = STORAGE.user_avatar.get(username) or "/static/images/user_default.png"
                        oauth_token_id = hashlib.sha256(str(token).encode("utf-8", errors='replace')).hexdigest()
                        get_token_store(username, 'oauth').add(oauth_token_id)

                        # Return valid token
                        return make_api_response({
                            "avatar": avatar,
                            "username": username,
                            "oauth_token_id": oauth_token_id,
                            "email_adr": email_adr
                        })
                    else:
                        return make_api_response({"err_code": 3},
                                                    err="User auto-creation is disabled",
                                                    status_code=403)
                else:
                    return make_api_response({"err_code": 5}, err="Invalid oAuth token provided", status_code=401)

            except OAuthError as err:
                return make_api_response({"err_code": 1}, err=str(err), status_code=401)

            except Exception as err:
                LOGGER.exception(str(err))
                return make_api_response({"err_code": 1, "exception": str(err)},
                                            err="Unhandled exception occured while processing oAuth token",
                                            status_code=401)
    else:
        return make_api_response({"err_code": 0}, err="oAuth disabled on the server", status_code=401)

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

    try:
        data = request.json
    except (BadRequest, UnsupportedMediaType):
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
                res = STORAGE.user.search(f"email:{email}", fl="*")
                if res.get('total', 0) == 1:
                    user = res['items'][0]
                    user.password = get_password_hash(password)
                    STORAGE.user.save(user.uname, user)
                    return make_api_response({"success": True})

        except Exception as e:
            LOGGER.warning(f"Failed to reset the user's password: {str(e)}")
            pass

        return make_api_response({"success": False},
                                 err="This reset link has expired, please restart the password reset process",
                                 status_code=403)

    return make_api_response({"success": False}, err="Invalid parameters passed", status_code=400)


@auth_api.route("/setup_otp/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.self_manage], count_toward_quota=False)
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

    user_data = STORAGE.user.get(uname, as_obj=False)
    if user_data['otp_sk'] is not None:
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

    try:
        data = request.json
    except (BadRequest, UnsupportedMediaType):
        data = request.values

    uname = data.get('user', None)
    password = data.get('password', None)
    password_confirm = data.get('password_confirm', None)
    email = data.get('email', None)

    if not uname or not password or not password_confirm or not email:
        return make_api_response({"success": False}, "Not enough information to proceed with user creation", 400)

    if STORAGE.user.exists(uname) or len(uname) < 3:
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
            "groups": [],
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

    try:
        data = request.json
    except (BadRequest, UnsupportedMediaType):
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
                    user_info.get('classification', Classification.UNRESTRICTED), user_info)

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
@api_login(audit=False, count_toward_quota=False)
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
    user_data = STORAGE.user.get(uname, as_obj=False)

    try:
        token = int(token)
    except ValueError:
        return make_api_response({'success': False}, err="This is not a valid OTP token", status_code=400)

    secret_key = flsk_session.pop('temp_otp_sk', None)
    if secret_key and get_totp_token(secret_key) == token:
        user_data['otp_sk'] = secret_key
        STORAGE.user.save(uname, user_data)
        return make_api_response({'success': True})
    else:
        flsk_session['temp_otp_sk'] = secret_key
        return make_api_response({'success': False}, err="OTP token does not match secret key", status_code=400)


def _prepare_flask_request(request) -> Dict[str, Any]:
    # If server is behind proxys or balancers use the HTTP_X_FORWARDED fields
    return {
        # TODO - the https switching disabled because everything redirects to http under the hood. Possibly just a
        # local misconfiguration issue, but it screws up the URL matching later on in `saml_process_assertion`.
        "https": "on",  # if request.scheme == "https" else "off",
        "http_host": request.host,
        "script_name": request.path,
        "get_data": request.args.copy(),
        # lowercase_urlencoding if using ADFS as IdP, https://github.com/onelogin/python-saml/pull/144
        "lowercase_urlencoding": config.auth.saml.lowercase_urlencoding,
        "post_data": request.form.copy()
    }


def _make_saml_auth(request_data: Dict[str, Any] = None) -> OneLogin_Saml2_Auth:
    request_data: Dict[str, Any] = request_data or _prepare_flask_request(request)
    return OneLogin_Saml2_Auth(request_data, config.auth.saml.settings.as_camel_case())
