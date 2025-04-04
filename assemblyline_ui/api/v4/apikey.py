import base64
import hashlib
import json
import os
import re
from io import BytesIO
from typing import Any, Dict
from urllib.parse import urlparse

from assemblyline.odm.models.apikey import APIKEY_ID_DELIMETER, FORBIDDEN_APIKEY_CHARACTERS, get_apikey_id, split_apikey_id
from assemblyline_ui.api.base import make_subapi_blueprint
from assemblyline.odm.models.user import (ACL_MAP, ROLES, USER_ROLES, USER_TYPE_DEP, USER_TYPES, User, load_roles,
                                          load_roles_form_acls)

from assemblyline_ui.helper.user import API_PRIV_MAP, PRIV_API_MAP
from flask import current_app, redirect, request
from typing import List
from assemblyline.odm.models.config import ExternalLinks
from flask import request, session as flsk_session

from assemblyline.common.comms import send_activated_email, send_authorize_email
from assemblyline.common.isotime import DAY_IN_SECONDS, iso_to_epoch, now, now_as_iso
from assemblyline.common.security import (check_password_requirements, get_password_hash,
                                          get_password_requirement_message)
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.config import HASH_PATTERN_MAP
from assemblyline.odm.models.user import (ACL_MAP, ROLES, USER_ROLES, USER_TYPE_DEP, USER_TYPES, User, load_roles,
                                          load_roles_form_acls)
from assemblyline.odm.models.user_favorites import Favorite
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import APIKEY_MAX_DTL, APPS_LIST, CLASSIFICATION, CLASSIFICATION_ALIASES, DAILY_QUOTA_TRACKER, LOGGER, \
    STORAGE, UI_MESSAGING, VERSION, config, AI_AGENT, UI_METADATA_VALIDATION

from assemblyline_ui.http_exceptions import AccessDeniedException, InvalidDataException

from assemblyline.common.security import (
    get_password_hash,
    get_random_password,
)
from werkzeug.exceptions import BadRequest

SCOPES = {
    'r': ["R"],
    'w': ["W"],
    'rw': ["R", "W"],
    'c': ["C"]
}



SUB_API = 'apikey'
apikey_api = make_subapi_blueprint(SUB_API, api_version=4)


@apikey_api.route("/list/", methods=["GET"])
@api_login(require_role=[ROLES.administration], count_toward_quota=False)
def list_apikeys(**_):
    """
    List all apikeys of the system.

    Variables:
    None

    Arguments:
    offset        =>  Offset in the user index
    query         =>  Filter to apply to the user list
    rows          =>  Max number of user returned
    sort          =>  Sort order

    Data Block:
    None

    Result example:
    {
     "count": 100,               # Max number of apikeys
     "items": [{                 # List of apikey blocks
        "acl": ["R"],
        "roles": ['submission_view', ...],
        "creation_date" : "2025-03-24T17:52:57.132282Z",
        'expiry_ts': '2025-03-29T17:52:57.132013Z',
        'last_used': '2025-03-25T17:52:57.132013Z',
        'id': 'devkey+admin',
        'uname': 'admin',
        'key_name': 'devkey'
       }, ...],
     "total": 10,                # Total number of apikeys
     "offset": 0                 # Offset in the user index
    }
    """
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"
    sort = request.args.get('sort', "id asc")

    try:
        result = STORAGE.apikey.search(query, offset=offset, rows=rows, sort=sort, as_obj=False)
        result_items = result.get("items", [])

        result_filtered = []

        for item in result_items:
            item.pop("password", None)
            result_filtered.append(item)

        result["items"] = result_filtered

        LOGGER.info(result["items"])
        return make_api_response(result)
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@apikey_api.route("/<key_id>/", methods=["GET"])
@api_login(require_role=[ROLES.apikey_access], count_toward_quota=False)
def check_apikey_exists(key_id, **kwargs):
    """
    Check if a key_id exists in the database.

    Variables:
    key_id       =>  API Key Id

    Arguments:
    None

    Data Block:
    None

    API call example:
    GET /api/v1/apikey/devkey+admin/

    Result example:
        {
        "acl": ["R"],
        "roles": ['submission_view', ...],
        "creation_date" : "2025-03-24T17:52:57.132282Z",
        'expiry_ts': '2025-03-29T17:52:57.132013Z',
        'last_used': '2025-03-25T17:52:57.132013Z',
        'id': 'devkey+admin',
        'uname': 'admin',
        'key_name': 'devkey'
       }
    """

    apikey = STORAGE.apikey.get_if_exists(key_id, as_obj=False)

    if apikey:
        if apikey['uname'] != kwargs['user']['uname'] and ROLES.administration not in kwargs['user']['roles']:
            raise AccessDeniedException(f"You do not have access to the apikey ({key_id}).")
        else:
            apikey['id'] = key_id
            apikey.pop("password", None)
            return make_api_response(apikey)

    return make_api_response(None, "Cannot find APIKey with the given ID.", 404)




@apikey_api.route("add/", methods=["PUT"])
@api_login(require_role=[ROLES.apikey_access], count_toward_quota=False)
def add_apikey(  **kwargs):
    """
    Add an API Key for the currently logged in user with given privileges

    Variables:
    None

    Arguments:
    keyid (Optional): The keyid to be updated

    Data Block:
    {
        "priv": [acl permissions "C"/"W"/"R"/"E"],
        "uname": "<username of key owner>",
        "key_name": "<key name>",
        "expiry_ts": "<expiry timestampe>",
        "roles": ["<key role>", ...]
    }

    Result example:
    {
        "keypassword": <key_name>:<ramdomly_generated_password>,
        "uname": "<username of key owner>",
        "key_name": "<key name>",
        "expiry_ts": "<expiry timestampe>",
        "roles": ["<key role>", ...]
    }
    """

    user = kwargs['user'] # the user that requested apikey modification

    key_id = request.args['keyid'] if "keyid" in request.args else None
    key_name = request.json['key_name']
    create_key = "keyid" not in request.args


    # could be admin or the user themselves modifying the apikey
    key_uname = request.json['uname'] if "uname" in request.json else user['uname']
    key_user_data = STORAGE.user.get(key_uname, as_obj=False)
    new_key_id = get_apikey_id(key_name, key_uname)

    # check new key name and key id doesn't have forbidden characters
    regex = re.compile(FORBIDDEN_APIKEY_CHARACTERS)

    # check formatting of key_id is valid
    if key_id:
        if APIKEY_ID_DELIMETER not in key_id:
            return make_api_response("", err=f"APIKey id '{key_id}' is invalid", status_code=400)

        id_name, id_uname = split_apikey_id(key_id)

        if (regex.search(id_name) != None):
            return make_api_response("", err=f"APIKey '{key_id}' contains forbidden characters.", status_code=400)

        if ROLES.administration not in user['roles'] and user['uname'] != id_uname:
            return make_api_response("", err=f"You do not have the permission to modify API Key with id {key_id}", status_code=400)

    if (regex.search(key_name) != None):
        return make_api_response("", err=f"APIKey '{key_name}' contains forbidden characters.", status_code=400)


    # make sure user is not modifying key of another user if they are not admin
    if ROLES.administration not in user['roles'] and ("uname" in request.json and user["uname"] != request.json['uname']):
        return make_api_response("", err=f"You do not have the permission to modify API Key with id {key_id}", status_code=400)


    priv = sorted(set(request.json['priv']))
    old_apikey =  STORAGE.apikey.get_if_exists(key_id) if key_id else STORAGE.apikey.get_if_exists(new_key_id)

    if create_key and old_apikey:
        return make_api_response("", err=f"API Key '{key_name}' already exist.", status_code=400)
    elif not create_key and not old_apikey:
        return make_api_response("", err=f"API Key '{key_name}' does not exist and cannot be updated.", status_code = 404)
    elif (old_apikey and old_apikey['uname'] != user['uname']) and ROLES.administration not in user['roles']:
        return make_api_response("", err=f"You don't have the permission to update API Key '{key_name}'.", status_code = 400)

    if "".join(priv) not in PRIV_API_MAP:
        return make_api_response("", err=f"Invalid APIKey privilege '{priv}'. Choose between: {API_PRIV_MAP.keys()}",
                                 status_code=400)

    roles = None
    if priv == ["C"]:
        try:
            roles = [r for r in request.json['roles']
                     if r in load_roles(key_user_data['type'], key_user_data.get('roles', None))]
        except BadRequest:
            return make_api_response("", err="Invalid data block provided. Provide a list of roles as JSON.",
                                     status_code=400)
    else:
        roles = [r for r in load_roles_form_acls(priv, roles)
                if r in load_roles(key_user_data['type'], key_user_data.get('roles', None))]

    if not roles:
        return make_api_response(
            "", err="None of the roles you've requested for this key are allowed for this user.", status_code=400)


    expiry_ts = request.json['expiry_ts']

    if (APIKEY_MAX_DTL and  expiry_ts is None) or (APIKEY_MAX_DTL and (iso_to_epoch(expiry_ts) >= now(APIKEY_MAX_DTL*DAY_IN_SECONDS))):

        return make_api_response(
            "", err=f"The expiry_ts is more than the max apikey dtl of {APIKEY_MAX_DTL} days.", status_code=400)

    random_pass = get_random_password(length=48) if create_key else None
    new_apikey = {
        "acl": priv,
        "roles": roles,
        "uname": key_uname,
        "key_name":key_name,
        "expiry_ts": expiry_ts,

    }


    if create_key:
        new_apikey['password'] = get_password_hash(random_pass)

    if not create_key and old_apikey:
        new_apikey['creation_date'] = old_apikey["creation_date"]
        new_apikey['last_used'] = old_apikey['last_used']
        new_apikey['password'] = old_apikey['password']


    STORAGE.apikey.save(new_key_id, new_apikey)
    new_apikey.pop("password", None)


    return make_api_response({  "acl": priv,
                                "keypassword":  f"{key_name}:{random_pass}" if create_key else None,
                                "roles": roles,
                                "uname": key_uname,
                                "key_name":key_name,
                                "expiry_ts": expiry_ts,
                                "id": new_key_id
                              })


@apikey_api.route("/<key_id>/", methods=["DELETE"])
@api_login(require_role=[ROLES.apikey_access])
def delete_apikey(key_id, **kwargs):
    """
    Delete a hash from the apikey

    Variables:
    key_id       => key id to check

    Arguments:
    None

    Data Block:
    None

    API call example:
    DELETE /api/v1/apikey/devkey+user/

    Result example:
    {"success": True}
    """
    user = kwargs['user']

    apikey = STORAGE.apikey.get_if_exists(key_id)

    if ROLES.administration in user['roles'] :
        return make_api_response({'success': (apikey is not None) and STORAGE.apikey.delete(key_id)})
    else:

        apikey = STORAGE.apikey.get_if_exists(key_id, as_obj=False)
        if apikey and apikey['uname'] == user['uname']:
            return make_api_response({'success': (apikey is not None) and STORAGE.apikey.delete(key_id)})

    return make_api_response({'success': False})
