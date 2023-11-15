
import hashlib
import os
import re
import tempfile

from flask import request
import magic
import yara
import yaml

from assemblyline.common import forge
from assemblyline.common.constants import CONFIG_HASH, POST_PROCESS_CONFIG_KEY
from assemblyline.common.digests import get_sha256_for_file
from assemblyline.common.identify_defaults import magic_patterns, trusted_mimes
from assemblyline.common.postprocess import SubmissionFilter
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.actions import DEFAULT_POSTPROCESS_ACTIONS, PostprocessAction
from assemblyline.odm.models.tagging import Tagging
from assemblyline.odm.models.user import ROLES
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.events import EventSender
from assemblyline_core import PAUSABLE_COMPONENTS
from assemblyline_ui.config import LOGGER, STORAGE, UI_MESSAGING, config, redis_persistent
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint


SUB_API = 'system'
system_api = make_subapi_blueprint(SUB_API, api_version=4)
system_api._doc = "Perform system actions"

ADMIN_FILE_TTL = 60 * 60 * 24 * 365 * 100  # Just keep the file for 100 years...
al_re = re.compile(r"^[a-z]+(?:/[a-z0-9\-.+]+)+$")
constants = forge.get_constants()

event_sender = EventSender('system',
                           host=config.core.redis.nonpersistent.host,
                           port=config.core.redis.nonpersistent.port)
config_hash: Hash[str] = Hash(CONFIG_HASH, redis_persistent)

PREPARED_POSTPROCESSING_ACTIONS = {
    key: rule.as_primitives()
    for key, rule in DEFAULT_POSTPROCESS_ACTIONS.items()
}


@system_api.route("/system_message/", methods=["DELETE"])
@api_login(require_role=[ROLES.administration])
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
@api_login(require_role=[ROLES.administration])
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
@api_login(require_role=[ROLES.administration])
def get_tag_safelist(**_):
    """
    Get the current tag_safelist

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    <current tag_safelist.yml file>
    """
    default = request.args.get('default', 'false').lower() in ['true', '']

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        tag_safelist_yml = cache.get('tag_safelist_yml')
        if not tag_safelist_yml or default:
            yml_data = forge.get_tag_safelist_data()
            if yml_data:
                return make_api_response(yaml.safe_dump(yml_data))

            return make_api_response(None, "Could not find the tag_safelist.yml file", 404)

        return make_api_response(safe_str(tag_safelist_yml))


@system_api.route("identify/magic/", methods=["GET"])
@api_login(require_role=[ROLES.administration])
def get_identify_custom_magic_file(**_):
    """
    Get identify's current custom LibMagic file

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    <current custom.magic file>
    """
    default = request.args.get('default', 'false').lower() in ['true', '']

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        custom_magic = cache.get('custom_magic')
        if not custom_magic or default:
            with open(constants.MAGIC_RULE_PATH) as mfh:
                return make_api_response(mfh.read())

        return make_api_response(custom_magic.decode('utf-8'))


@system_api.route("identify/mimes/", methods=["GET"])
@api_login(require_role=[ROLES.administration])
def get_identify_trusted_mimetypes(**_):
    """
    Get identify's trusted mimetypes map

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    <current identify's trusted mimetypes map>
    """
    default = request.args.get('default', 'false').lower() in ['true', '']

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        custom_mime = cache.get('custom_mimes')
        if not custom_mime or default:
            return make_api_response(yaml.safe_dump(trusted_mimes))

        return make_api_response(custom_mime.decode('utf-8'))


@system_api.route("identify/patterns/", methods=["GET"])
@api_login(require_role=[ROLES.administration])
def get_identify_magic_patterns(**_):
    """
    Get identify's magic patterns

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    <current identify's magic patterns>
    """
    default = request.args.get('default', 'false').lower() in ['true', '']

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        custom_patterns = cache.get('custom_patterns')
        if not custom_patterns or default:
            return make_api_response(yaml.safe_dump(magic_patterns))

        return make_api_response(custom_patterns.decode('utf-8'))


@system_api.route("identify/yara/", methods=["GET"])
@api_login(require_role=[ROLES.administration])
def get_identify_custom_yara_file(**_):
    """
    Get identify's current custom Yara file

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    <current custom.yara file>
    """
    default = request.args.get('default', 'false').lower() in ['true', '']

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        custom_yara = cache.get('custom_yara')
        if not custom_yara or default:
            with open(constants.YARA_RULE_PATH) as mfh:
                return make_api_response(mfh.read())

        return make_api_response(custom_yara.decode('utf-8'))


@system_api.route("/status/<component>/", methods=["GET"])
@api_login()
def get_system_status(component, **_):
    """
    Get the status of system components

    Variables:
    component           => Component you want to get the status for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {'status': true}
    """
    system = Hash("system", host=redis_persistent)
    if component == 'ALL':
        return make_api_response(
            {c: system.get(f'{c}.active') or False for c in PAUSABLE_COMPONENTS})
    else:
        if component not in PAUSABLE_COMPONENTS:
            make_api_response({}, err=f"Component {component} does not exist or is always active.")

        status = system.get(f'{component}.active') or False

        return make_api_response({component: status})


@system_api.route("/system_message/", methods=["PUT", "POST"])
@api_login(require_role=[ROLES.administration])
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
@api_login(require_role=[ROLES.administration], allow_readonly=False)
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
                for key, values in yml_data[tag_type].items():
                    if key not in fields:
                        raise Exception(f'{key} is not a valid tag type')

                    if not isinstance(values, list):
                        raise Exception(f'Value for {key} should be a list of strings')

                    for value in values:
                        try:
                            re.compile(value)
                        except Exception as e:
                            raise Exception(f"{e} in '{value}'")

    except Exception as e:
        return make_api_response(None, f"Invalid tag_safelist.yml file submitted: {str(e)}", 400)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        cache.save('tag_safelist_yml', tag_safelist_yml.encode('utf-8'), ttl=ADMIN_FILE_TTL, force=True)

    return make_api_response({'success': True})


@system_api.route("identify/magic/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def put_identify_custom_magic_file(**_):
    """
    Save a new version of identify's custom LibMagic file

    Variables:
    None

    Arguments:
    None

    Data Block:
    <current custom.magic file>

    Result example:
    {"success": True}
    """
    data = request.json.encode('utf-8')

    magic_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            magic_file = tmp.name
            tmp.write(data)

        try:
            test = magic.magic_open(magic.MAGIC_CONTINUE + magic.MAGIC_RAW)
            magic.magic_load(test, magic_file)
        except magic.MagicException:
            return make_api_response({'success': False}, "The magic file you have submitted is invalid.", 400)
    finally:
        if magic_file and os.path.exists(magic_file):
            os.unlink(magic_file)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        if hashlib.sha256(data).hexdigest() == get_sha256_for_file(constants.MAGIC_RULE_PATH):
            cache.delete('custom_magic')
        else:
            cache.save('custom_magic', data, ttl=ADMIN_FILE_TTL, force=True)

    # Notify components watching to reload magic file
    event_sender.send('identify', 'magic')

    return make_api_response({'success': True})


@system_api.route("identify/mimes/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def put_identify_trusted_mimetypes(**_):
    """
    Save a new version of identify's trusted mimetypes file

    Variables:
    None

    Arguments:
    None

    Data Block:
    <new trusted mimetypes file>

    Result example:
    {"success": True}
    """
    data = request.json.encode('utf-8')

    try:
        mimes = yaml.safe_load(data)
        for k, v in mimes.items():
            if not isinstance(k, str) or not al_re.match(k):
                raise ValueError(f"Invalid mimetype in item: [{k}: {v}]")

            if not isinstance(v, str) or not al_re.match(v):
                raise ValueError(f"Invalid AL type in item [{k}: {v}]")

    except Exception as e:
        return make_api_response({'success': False}, err=str(e), status_code=400)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        if yaml.safe_dump(mimes) == yaml.safe_dump(trusted_mimes):
            cache.delete('custom_mimes')
        else:
            cache.save('custom_mimes', data, ttl=ADMIN_FILE_TTL, force=True)

    # Notify components watching to reload trusted mimes
    event_sender.send('identify', 'mimes')

    return make_api_response({'success': True})


@system_api.route("identify/patterns/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def put_identify_magic_patterns(**_):
    """
    Save a new version of identify's magic patterns file

    Variables:
    None

    Arguments:
    None

    Data Block:
    <new magic patterns file>

    Result example:
    {"success": True}
    """
    data = request.json.encode('utf-8')

    try:
        patterns = yaml.safe_load(data)
        for pattern in patterns:
            if 'al_type' not in pattern:
                raise ValueError(f"Missing 'al_type' in pattern: {str(pattern)}")

            if not al_re.match(pattern['al_type']):
                raise ValueError(f"Invalid 'al_type' in pattern: {str(pattern)}")

            if 'regex' not in pattern:
                raise ValueError(f"Missing 'regex' in pattern: {str(pattern)}")

            try:
                re.compile(pattern['regex'])
            except Exception as e:
                raise ValueError(f"Invalid regular expression in pattern: '{pattern['regex']}' ({e})")
    except Exception as e:
        return make_api_response({'success': False}, err=str(e), status_code=400)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        if yaml.safe_dump(patterns) == yaml.safe_dump(magic_patterns):
            cache.delete('custom_patterns')
        else:
            cache.save('custom_patterns', data, ttl=ADMIN_FILE_TTL, force=True)

    # Notify components watching to reload magic patterns
    event_sender.send('identify', 'patterns')

    return make_api_response({'success': True})


@system_api.route("identify/yara/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def put_identify_custom_yara_file(**_):
    """
    Save a new version of identify's custom Yara file

    Variables:
    None

    Arguments:
    None

    Data Block:
    <current custom.yara file>

    Result example:
    {"success": True}
    """
    data = request.json.encode('utf-8')

    yara_file = None
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            yara_file = tmp.name
            tmp.write(data)

        try:
            yara_default_externals = {'mime': '', 'magic': '', 'type': ''}
            yara.compile(filepaths={"default": yara_file}, externals=yara_default_externals)
        except Exception as e:
            message = str(e).replace(yara_file, "custom.yara line ")
            return make_api_response(
                {'success': False},
                f"The Yara file you have submitted is invalid: {message}", 400)
    finally:
        if yara_file and os.path.exists(yara_file):
            os.unlink(yara_file)

    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        if hashlib.sha256(data).hexdigest() == get_sha256_for_file(constants.YARA_RULE_PATH):
            cache.delete('custom_yara')
        else:
            cache.save('custom_yara', data, ttl=ADMIN_FILE_TTL, force=True)

    # Notify components watching to reload yara file
    event_sender.send('identify', 'yara')

    return make_api_response({'success': True})


@system_api.route("/status/<component>/", methods=["PUT", "POST"])
@api_login(require_role=[ROLES.administration])
def put_system_status(component, **_):
    """
    Set the status of system components.

    Variables:
    component           => Component that staus change should apply to

    Arguments:
    active              => Should the component be active? (True or False)

    Data Block:
    None

    Result example:
    {"success": true}
    """

    system = Hash("system", host=redis_persistent)
    component = component.lower()
    if component not in PAUSABLE_COMPONENTS:
        return make_api_response(None, err=f"Component {component} is not allowed to change status.", status_code=403)

    status = request.args.get('active').lower()
    if not status or status not in ['true', 'false']:
        return make_api_response(
            None, err=f"{component} given invalid status value. Must be true or false.", status_code=400)

    # Set value in persistent redis to maintain state during updates
    system.set(f'{component}.active', status == 'true')

    # Notify the component about the status change
    event_sender.send(f'{component}.active', status == 'true')

    return make_api_response({'success': True})


@system_api.route("/actions/", methods=["GET"])
@api_login(require_role=[ROLES.administration])
def get_post_processing_actions(**_):
    """
    Get rules to determine post processing actions.

    Variables:
    None

    Arguments:
    default    =>  Load the default values that came with the system

    Data Block:
    None

    Result example:
    {
        "rule_name": {
            "enabled": true,
            "run_on_completed": true,
            "filter": "max_score: >=1000",
            "raise_alert": true
        }
    }
    """
    default = request.args.get('default', 'false').lower() in ['true', '']
    if not default:
        # Try loading information from redis
        data = config_hash.get(POST_PROCESS_CONFIG_KEY)
        if data:
            return make_api_response(data)

        # Fall back to legacy storage
        with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
            try:
                cached_rules = cache.get('postprocess_actions')
                if cached_rules:
                    return make_api_response(cached_rules.decode('utf-8'))
            except Exception:
                LOGGER.exception("Bad actions config")

    return make_api_response(yaml.safe_dump(PREPARED_POSTPROCESSING_ACTIONS))


@system_api.route("/actions/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def put_post_processing_actions(**_):
    """
    Save a new version of the post processing actions.

    Variables:
    None

    Arguments:
    None

    Data Block:
    string encoded YAML dictionary of PostprocessingAction.

    Result example:
    {"success": True}
    """
    actions = request.json.encode('utf-8')

    try:
        actions_data = yaml.safe_load(actions)
        if not isinstance(actions_data, dict):
            raise ValueError("Unexpected input: " + actions + ';' + actions_data)
    except Exception as e:
        return make_api_response({'success': False}, f"Invalid post processing actions file submitted: {str(e)}", 400)

    # Validate the data
    parsed_rules = {}
    for rule_name, rule_data in actions_data.items():
        try:
            action = PostprocessAction(rule_data, ignore_extra_values=False)
            parsed_rules[rule_name] = action
            try:
                fltr = SubmissionFilter(action.filter)
                if not fltr.cache_safe and action.run_on_cache:
                    return make_api_response(
                        {'success': False, 'rule': rule_name, 'reason': 'cache_filter'},
                        err=f"The filter on rule {rule_name} could not be "
                            f"run on cache hits as requested: {action.filter}",
                        status_code=400
                    )
            except Exception as error:
                return make_api_response(
                    {'success': False, 'rule': rule_name, 'reason': 'filter'},
                    err=f"Error parsing filter on rule {rule_name}: {error}",
                        status_code=400
                )
        except Exception as error:
            return make_api_response(
                {'success': False, 'rule': rule_name, 'reason': 'parsing'},
                err=f"Error parsing rule {rule_name}: {error}",
                status_code=400
            )

    # Save data
    config_hash.set(POST_PROCESS_CONFIG_KEY, actions.decode())

    # Clean up legacy data
    with forge.get_cachestore('system', config=config, datastore=STORAGE) as cache:
        cache.delete('postprocess_actions')

    # Notify components watching to reload file
    event_sender.send('postprocess', 'rules')

    return make_api_response({'success': True})
