
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap2 import AttestationObject, AttestedCredentialData
from fido2.server import U2FFido2Server
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import PublicKeyCredentialRpEntity

from flask import session, request

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import make_api_response, api_login, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, config

SUB_API = 'webauthn'
webauthn_api = make_subapi_blueprint(SUB_API, api_version=4)
webauthn_api._doc = "Perfom 2-Factor authentication using webauthn protocol"

rp = PublicKeyCredentialRpEntity(config.ui.fqdn, "Assemblyline server")
server = U2FFido2Server(f"https://{config.ui.fqdn}", rp)


@webauthn_api.route("/authenticate/begin/<username>/", methods=["GET"])
def authenticate_begin(username, **_):
    """
    Begin authentication procedure

    Variables:
    username     user name of the user you want to login with

    Arguments:
    None

    Data Block:
    None

    Result example:
    <WEBAUTHN_AUTHENTICATION_DATA>
    """
    user = STORAGE.user.get(username, as_obj=False)
    if not user:
        return make_api_response({'success': False}, err="Bad Request", status_code=400)

    session.pop('state', None)
    security_tokens = user.get('security_tokens', {}) or {}
    credentials = [AttestedCredentialData(websafe_decode(x)) for x in security_tokens.values()]

    auth_data, state = server.authenticate_begin(credentials)
    session['state'] = state

    return make_api_response(list(cbor.encode(auth_data)))


@webauthn_api.route("/register/begin/", methods=["POST"])
@api_login(audit=False, require_role=[ROLES.self_manage])
def register_begin(**kwargs):
    """
    Begin registration of a security token

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <WEBAUTHN_REGISTRATION_DATA>
    """
    uname = kwargs['user']['uname']
    user = STORAGE.user.get(uname, as_obj=False)

    if user['otp_sk'] is None:
        return make_api_response(None, err="OTP must be setup before adding security tokens", status_code=403)

    session.pop('state', None)
    security_tokens = user.get('security_tokens', {}) or {}

    registration_data, state = server.register_begin(
        dict(
            id=user['uname'].encode('utf-8'),
            name=user['uname'],
            displayName=user['name'],
            icon=f"https://{config.ui.fqdn}/static/images/favicon.ico"
        ),
        credentials=[AttestedCredentialData(websafe_decode(x)) for x in security_tokens.values()]
    )

    session['state'] = state

    return make_api_response(list(cbor.encode(registration_data)))


# noinspection PyBroadException
@webauthn_api.route("/register/complete/<name>/", methods=["POST"])
@api_login(audit=False, require_role=[ROLES.self_manage])
def register_complete(name, **kwargs):
    """
    Complete registration of the new key and save it under a given name

    Variables:
    name    => Name of the token

    Arguments:
    data    => Response to the enroll challenge

    Data Block:
    None

    Result example:
    {
     "success": True
    }
    """
    uname = kwargs['user']['uname']
    user = STORAGE.user.get(uname, as_obj=False)
    data = cbor.decode(bytes(request.json))

    client_data = ClientData(data['clientDataJSON'])
    att_obj = AttestationObject(data['attestationObject'])

    auth_data = server.register_complete(session.pop('state', None), client_data, att_obj)

    security_tokens = user.get('security_tokens', {})
    if name in security_tokens:
        return make_api_response({'success': False}, err="A token with this name already exist", status_code=400)

    security_tokens[name] = websafe_encode(auth_data.credential_data)
    user['security_tokens'] = security_tokens

    return make_api_response({"success": STORAGE.user.save(uname, user)})


@webauthn_api.route("/remove/<name>/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.self_manage])
def remove(name, **kwargs):
    """
    Remove a given security token

    Variables:
    name    =>  Name of the token to remove

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
    user = STORAGE.user.get(uname, as_obj=False)
    security_tokens = user.get('security_tokens', {})
    if isinstance(security_tokens, list):
        security_tokens = {"default": d for d in security_tokens}
    security_tokens.pop(name, None)
    user['security_tokens'] = security_tokens

    return make_api_response({'success': STORAGE.user.save(uname, user)})
