
from fido2 import cbor
from fido2.client import ClientData
from fido2.ctap1 import RegistrationData
from fido2.ctap2 import AttestationObject, AuthenticatorData, AttestedCredentialData
from fido2.server import U2FFido2Server
from fido2.utils import websafe_encode, websafe_decode
from fido2.webauthn import PublicKeyCredentialRpEntity

from flask import session, request

from assemblyline_ui.api.base import make_api_response, api_login, make_subapi_blueprint, make_binary_response
from assemblyline_ui.config import STORAGE, APP_ID, config

SUB_API = 'webauthn'
webauthn_api = make_subapi_blueprint(SUB_API, api_version=4)
webauthn_api._doc = "Perfom 2-Factor authentication using webauthn protocol"

rp = PublicKeyCredentialRpEntity(config.ui.fqdn, "Assemblyline server")
server = U2FFido2Server(f"https://{config.ui.fqdn}", rp)


@webauthn_api.route("/authenticate/begin/<username>/", methods=["GET"])
def sign(username, **_):
    """
    Start signin in procedure

    Variables:
    username     user name of the user you want to login with

    Arguments:
    None

    Data Block:
    None

    Result example:
    <U2F_SIGN_IN_CHALLENGE_BLOCK>
    """
    user = STORAGE.user.get(username, as_obj=False)
    if not user:
        return make_api_response({'success': False}, err="Bad Request", status_code=400)

    u2f_devices = user.get('u2f_devices', {})
    if isinstance(u2f_devices, list):
        u2f_devices = {"default": d for d in u2f_devices}

    challenge = begin_authentication(APP_ID, list(u2f_devices.values()))
    session['_u2f_challenge_'] = challenge.json

    return make_api_response(challenge.data_for_client)


@webauthn_api.route("/register/begin/", methods=["POST"])
@api_login(audit=False)
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
    <WEBAUTHN_REGISTRATION_DICT>
    """
    uname = kwargs['user']['uname']
    user = STORAGE.user.get(uname, as_obj=False)

    session.pop('state', None)

    registration_data , state = server.register_begin(
        dict(
            id=user['uname'].encode('utf-8'),
            name=user['uname'],
            displayName=user['name'],
            icon=f"https://{config.ui.fqdn}/static/images/favicon.ico"
        ),
        credentials=[AttestedCredentialData(websafe_decode(x)) for x in user['u2f_devices'].values()]
    )

    session['state'] = state

    cbor_data = cbor.encode(registration_data)
    return make_api_response(list(cbor_data))


# noinspection PyBroadException
@webauthn_api.route("/register/complete/<name>/", methods=["POST"])
@api_login(audit=False)
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

    u2f_devices = user.get('u2f_devices', {})
    if name in u2f_devices:
        return make_api_response({'success': False}, err="A token with this name already exist", status_code=400)

    u2f_devices[name] = websafe_encode(auth_data.credential_data)
    user['u2f_devices'] = u2f_devices

    return make_api_response({"success": STORAGE.user.save(uname, user)})


@webauthn_api.route("/remove/<name>/", methods=["GET"])
@api_login(audit=False)
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
    u2f_devices = user.get('u2f_devices', {})
    if isinstance(u2f_devices, list):
        u2f_devices = {"default": d for d in u2f_devices}
    u2f_devices.pop(name, None)
    user['u2f_devices'] = u2f_devices

    return make_api_response({'success': STORAGE.user.save(uname, user)})
