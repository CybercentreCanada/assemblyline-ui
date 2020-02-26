import json
import os
import random
import string

import webauthn

from flask import session, request

from assemblyline_ui.api.base import make_api_response, api_login, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, APP_ID, config

SUB_API = 'webauthn'
webauthn_api = make_subapi_blueprint(SUB_API, api_version=4)
webauthn_api._doc = "Perfom 2-Factor authentication using webauthn protocol"

TRUST_ANCHOR_DIR = 'trusted_attestation_roots'


def generate_challenge(challenge_len):
    return ''.join([
        random.SystemRandom().choice(string.ascii_letters + string.digits)
        for _ in range(challenge_len)
    ])


def generate_ukey():
    """Its value's id member is required, and contains an identifier
    for the account, specified by the Relying Party. This is not meant
    to be displayed to the user, but is used by the Relying Party to
    control the number of credentials - an authenticator will never
    contain more than one credential for a given Relying Party under
    the same id.
    A unique identifier for the entity. For a relying party entity,
    sets the RP ID. For a user account entity, this will be an
    arbitrary string specified by the relying party.
    """
    return generate_challenge(20)


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


@webauthn_api.route("/begin_activate/", methods=["GET"])
@api_login(audit=False)
def begin_activate(**kwargs):
    """
    Begin activation of a security token

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

    if 'challenge' in session:
        del session['challenge']

    challenge = generate_challenge(32)
    ukey = generate_ukey()

    session['challenge'] = challenge

    make_credential_options = webauthn.WebAuthnMakeCredentialOptions(
        challenge, "Assemblyline", config.ui.fqdn, ukey, uname, user['name'],
        f'https://{config.ui.fqdn}/static/images/favicon.ico')

    return make_api_response(make_credential_options.registration_dict)


# noinspection PyBroadException
@webauthn_api.route("/verify_credential_info/<name>/", methods=["POST"])
@api_login(audit=False)
def verify_credential_info(name, **kwargs):
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
    data = request.json

    challenge = session['challenge']

    trust_anchor_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)).split("api")[0], "static", TRUST_ANCHOR_DIR)
    trusted_attestation_cert_required = True
    self_attestation_permitted = True
    none_attestation_permitted = True

    webauthn_registration_response = webauthn.WebAuthnRegistrationResponse(
        config.ui.fqdn,
        f"https://{config.ui.fqdn}",
        data,
        challenge,
        trust_anchor_dir,
        trusted_attestation_cert_required,
        self_attestation_permitted,
        none_attestation_permitted,
        uv_required=False)  # User Verification

    try:
        webauthn_credential = webauthn_registration_response.verify()
    except Exception as e:
        return make_api_response({'success': False}, err="Could not verify the security token", status_code=400)

    u2f_devices = user.get('u2f_devices', {})
    if name in u2f_devices:
        return make_api_response({'success': False}, err="A token with this name already exist", status_code=400)

    webauthn_credential_dict = dict(
        credential_id=webauthn_credential.credential_id.decode('utf-8'),
        public_key=webauthn_credential.public_key.decode('utf-8'),
        sign_count=webauthn_credential.sign_count
    )
    u2f_devices[name] = json.dumps(webauthn_credential_dict)

    user['u2f_devices'] = u2f_devices

    return make_api_response({"success": STORAGE.user.save(uname, user)})


@webauthn_api.route("/sign/<username>/", methods=["GET"])
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
