
from flask import request

from assemblyline.common import forge
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.tagging import Tagging

from assemblyline_ui.config import STORAGE, UI_MESSAGING
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
import yaml


Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'system'
system_api = make_subapi_blueprint(SUB_API, api_version=4)
system_api._doc = "Perform system actions"

ADMIN_FILE_TTL = 60 * 60 * 24 * 365 * 100  # Just keep the file for 100 years...


@system_api.route("/system_message/", methods=["DELETE"])
@api_login(require_type=['admin'], required_priv=['W'])
def clear_system_message(**_):
    """
    Clear the current system message

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {"success": true}
    """
    UI_MESSAGING.pop('system_message')
    return make_api_response({'success': True})


@system_api.route("/system_message/", methods=["GET"])
@api_login(require_type=['admin'], required_priv=['R'])
def get_system_message(**_):
    """
    Get the current system message

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
      "title": "Message title",
      "user": "admin",
      "severity": "info",
      "message": "This is a test message"
    }
    """
    return make_api_response(UI_MESSAGING.get('system_message'))


@system_api.route("/tag_safelist/", methods=["GET"])
@api_login(require_type=['admin'], required_priv=['R'])
def get_tag_safelist(**_):
    """
    Get the current tag_safelist

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    <current tag_safelist.yml file>
    """
    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        tag_safelist_yml = cache.get('tag_safelist_yml')
        if not tag_safelist_yml:
            yml_data = forge.get_tag_safelist_data()
            if yml_data:
                return make_api_response(yaml.safe_dump(yml_data))

            return make_api_response(None, "Could not find the tag_safelist.yml file", 404)

        return make_api_response(safe_str(tag_safelist_yml))


@system_api.route("/system_message/", methods=["PUT", "POST"])
@api_login(require_type=['admin'], required_priv=['W'])
def set_system_message(**kwargs):
    """
    Set the current system message

    Variables:
    None

    Arguments:
    None

    Data Block:
    {
      "title": "Message title",
      "severity": "info",
      "message": "This is a test message"
    }

    Result example:
    {"success": true}
    """
    msg = request.json
    if isinstance(msg, dict) and 'severity' in msg and 'message' in msg:
        msg['user'] = kwargs['user']['uname']
        msg = {k: v for k, v in msg.items() if k in ['severity', 'message', 'title', 'user']}
        UI_MESSAGING.set('system_message', msg)
        return make_api_response({"success": True})

    return make_api_response(None, "Invalid system message submitted.", 400)


@system_api.route("/tag_safelist/", methods=["PUT"])
@api_login(require_type=['admin'], allow_readonly=False, required_priv=['W'])
def put_tag_safelist(**_):
    """
    Save a new version of the tag_safelist file

    Variables:
    None

    Arguments:
    None

    Data Block:
    <new tag_safelist.yml file>

    Result example:
    {"success": true}
    """
    tag_safelist_yml = request.json

    try:
        yml_data = yaml.safe_load(tag_safelist_yml)
        for key in yml_data.keys():
            if key not in ['match', 'regex']:
                raise Exception('Invalid key found.')

            fields = Tagging.flat_fields()
            for tag_type in ['match', 'regex']:
                for key, value in yml_data[tag_type].items():
                    if key not in fields:
                        raise Exception(f'{key} is not a valid tag type')

                    if not isinstance(value, list):
                        raise Exception(f'Value for {key} should be a list of strings')
    except Exception as e:
        return make_api_response(None, f"Invalid tag_safelist.yml file submitted: {str(e)}", 400)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        cache.save('tag_safelist_yml', tag_safelist_yml.encode('utf-8'), ttl=ADMIN_FILE_TTL, force=True)

    return make_api_response({'success': True})
