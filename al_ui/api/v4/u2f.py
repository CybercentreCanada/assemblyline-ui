
from flask import session, request
from u2flib_server.u2f import begin_registration, begin_authentication, complete_registration

from al_ui.api.base import make_api_response, api_login, make_subapi_blueprint
from al_ui.config import STORAGE, APP_ID

SUB_API = 'u2f'
u2f_api = make_subapi_blueprint(SUB_API, api_version=4)
u2f_api._doc = "Perfom 2-Factor authentication with a FIDO U2F USB Key"

U2F_CLIENT_ERROR_MAP = {
    1: "Unspecified error",
    2: "Bad Request - The URL used to access the site may mismatch the seed FQDN value",
    3: "Client configuration not supported",
    4: "Device ineligible or already registered",
    5: "Timed out"
}


@u2f_api.route("/remove/<name>/", methods=["GET"])
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


@u2f_api.route("/enroll/", methods=["GET"])
@api_login(audit=False)
def enroll(**kwargs):
    """
    Begin registration of a new U2F Security Token

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <U2F_ENROLL_CHALLENGE_BLOCK>
    """
    uname = kwargs['user']['uname']
    user = STORAGE.user.get(uname, as_obj=False)

    u2f_devices = user.get('u2f_devices', {})
    if isinstance(u2f_devices, list):
        u2f_devices = {"default": d for d in u2f_devices}

    u2f_devices = list(u2f_devices.values())
    current_enroll = begin_registration(APP_ID, u2f_devices)
    session['_u2f_enroll_'] = current_enroll.json

    return make_api_response(current_enroll.data_for_client)


@u2f_api.route("/bind/<name>/", methods=["POST"])
@api_login(audit=False)
def bind(name, **kwargs):
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
    data = request.json
    if "errorCode" in data:
        return make_api_response({'success': False}, err=U2F_CLIENT_ERROR_MAP[data['errorCode']], status_code=400)

    user = STORAGE.user.get(uname, as_obj=False)
    current_enroll = session.pop('_u2f_enroll_')

    try:
        device, cert = complete_registration(current_enroll, data, [APP_ID])
    except Exception as e:
        return make_api_response({'success': False}, err=str(e), status_code=400)

    u2f_devices = user.get('u2f_devices', {})
    if isinstance(u2f_devices, list):
        u2f_devices = {"default": d for d in u2f_devices}

    if name in u2f_devices:
        return make_api_response({'success': False}, err="A token with this name already exist", status_code=400)

    u2f_devices[name] = device.json

    user['u2f_devices'] = u2f_devices

    return make_api_response({"success": STORAGE.user.save(uname, user)})


@u2f_api.route("/sign/<username>/", methods=["GET"])
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
