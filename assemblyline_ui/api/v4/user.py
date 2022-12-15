from flask import request

from assemblyline.common.comms import send_activated_email, send_authorize_email
from assemblyline.common.isotime import now_as_iso
from assemblyline.common.security import (check_password_requirements, get_password_hash,
                                          get_password_requirement_message)
from assemblyline.datastore.exceptions import SearchException
from assemblyline.odm.models.user import ROLES, USER_ROLES, USER_TYPE_DEP, USER_TYPES, User, load_roles
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import APPS_LIST, CLASSIFICATION, LOGGER, STORAGE, UI_MESSAGING, VERSION, config
from assemblyline_ui.helper.search import list_all_fields
from assemblyline_ui.helper.service import simplify_service_spec, ui_to_submission_params
from assemblyline_ui.helper.user import (get_dynamic_classification, load_user_settings, save_user_account,
                                         save_user_settings)
from assemblyline_ui.http_exceptions import AccessDeniedException, InvalidDataException

SUB_API = 'user'
user_api = make_subapi_blueprint(SUB_API, api_version=4)
user_api._doc = "Manage the different users of the system"

ALLOWED_FAVORITE_TYPE = ["alert", "search", "submission", "signature", "error"]
classification_definition = CLASSIFICATION.get_parsed_classification_definition()


@user_api.route("/whoami/", methods=["GET"])
@api_login(required_priv=["R"])
def who_am_i(**kwargs):
    """
    Return the currently logged in user as well as the system configuration

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "agrees_with_tos": None,                   # Date the user agreed with TOS
     "avatar": "data:image/jpg...",             # Avatar data block
     "c12nDef": {},                             # Classification definition block
     "classification": "TLP:W",                 # Classification of the user
     "configuration": {                         # Configuration block
       "auth": {                                  # Authentication Configuration
         "allow_2fa": True,                         # Is 2fa Allowed for the user
         "allow_apikeys": True,                     # Are APIKeys allowed for the user
         "allow_extended_apikeys": True,            # Allow user to generate extended access API Keys
         "allow_security_tokens": True,             # Are Security tokens allowed for the user
       },
       "submission": {                            # Submission Configuration
         "dtl": 10,                                 # Default number of days submission stay in the system
         "max_dtl": 30,                             # Maximum number of days submission stay in the system
         "sha256_sources": [],                      # List of sources SHA256 submissions lookup on other systems
         "verdicts": {                              # Verdict scoring configuration
            "info": 0,                                # Default minimum score for info
            "suspicious": 300,                        # Default minimum score for suspicious
            "highly_suspicious": 700,                 # Default minimum score for highly_suspicious
            "malicious": 1000,                        # Default minimum score for malicious
         }
       },
       "system": {                                # System Configuration
         "organisation": "ACME",                    # Organisation name
         "type": "production",                      # Type of deployment
         "version": "4.1"                           # Assemblyline version
       },
       "ui": {                                    # UI Configuration
         "alerting_meta": {                         # Alert metadata configuration
            "important": [],                          # List of metadata fields that should always be displayed
            "subject": [],                            # List of metadata fields where to fetch email subject
            "url": []                                 # List of metadata fields where to fetch URLS
         },
         "allow_malicious_hinting": True,           # Are users allowed to set the malicious flag before processing
         "allow_raw_downloads": True,               # Are users allowed to download files in their raw format?
         "allow_zip_downloads": True,               # Are users allowed to download files as password-protected ZIPs?
         "allow_replay": False,                     # Are users allowed to continue submissions on another server
         "allow_url_submissions": True,             # Are URL submissions allowed
         "apps": [],                                # List of apps shown in the apps switcher
         "banner": None,                            # Banner displayed on the submit page
         "banner_level": True,                      # Banner color (info, success, warning, error)
         "read_only": False,                        # Is the interface to be displayed in read-only mode
         "rss_feeds": [],                           # List of RSS feeds
         "services_feed": "",                       # Feed of all the services available
         "tos": True,                               # Are terms of service set in the system
         "tos_lockout": False,                      # Will agreeing to TOS lockout the user
         "tos_lockout_notify": False                # Will admin be auto-notified when a user is locked out
       }
     },
     "email": "basic.user@assemblyline.local",  # Email of the user
     "groups": ["USERS"],                       # Groups the user if member of
     "indexes": {},                             # Search indexes definitions
     "is_active": True,                         # Is the user active
     "name": "Basic user",                      # Name of the user
     "type": ["admin"],                 # Roles the user is member of
     "uname": "sgaron-cyber"                    # Username of the current user
    }

    """
    user_data = {
        k: v for k, v in kwargs['user'].items()
        if k in
        ["agrees_with_tos", "classification", "email", "groups", "is_active", "name", "roles", "type", "uname"]}

    user_data['avatar'] = STORAGE.user_avatar.get(kwargs['user']['uname'])
    user_data['username'] = user_data.pop('uname')
    user_data['is_admin'] = "administration" in user_data['roles']

    # System configuration
    user_data['c12nDef'] = classification_definition
    user_data['configuration'] = {
        "auth": {
            "allow_2fa": config.auth.allow_2fa,
            "allow_apikeys": config.auth.allow_apikeys,
            "allow_extended_apikeys": config.auth.allow_extended_apikeys,
            "allow_security_tokens": config.auth.allow_security_tokens,
        },
        "datastore": {
            "archive": {
                "enabled": config.datastore.archive.enabled
            }
        },
        "submission": {
            "dtl": config.submission.dtl,
            "max_dtl": config.submission.max_dtl,
            "sha256_sources": [x.name for x in config.submission.sha256_sources
                               if CLASSIFICATION.is_accessible(kwargs['user']['classification'],
                                                               x.classification)],
            "verdicts": {
                "info": config.submission.verdicts.info,
                "suspicious": config.submission.verdicts.suspicious,
                "highly_suspicious": config.submission.verdicts.highly_suspicious,
                "malicious": config.submission.verdicts.malicious
            }
        },
        "system": {
            "organisation": config.system.organisation,
            "type": config.system.type,
            "version": VERSION
        },
        "ui": {
            "alerting_meta": {
                "important": config.ui.alerting_meta.important,
                "subject": config.ui.alerting_meta.subject,
                "url": config.ui.alerting_meta.url
            },
            "allow_malicious_hinting": config.ui.allow_malicious_hinting,
            "allow_raw_downloads": config.ui.allow_raw_downloads,
            "allow_zip_downloads": config.ui.allow_zip_downloads,
            "allow_replay": config.ui.allow_replay,
            "allow_url_submissions": config.ui.allow_url_submissions,
            "apps": [x for x in APPS_LIST['apps']
                     if CLASSIFICATION.is_accessible(kwargs['user']['classification'],
                                                     x['classification'] or CLASSIFICATION.UNRESTRICTED,
                                                     ignore_invalid=True)],
            "banner": config.ui.banner,
            "banner_level": config.ui.banner_level,
            "read_only": config.ui.read_only,
            "rss_feeds": config.ui.rss_feeds,
            "services_feed": config.ui.services_feed,
            "tos": config.ui.tos not in [None, ""],
            "tos_lockout": config.ui.tos_lockout,
            "tos_lockout_notify": config.ui.tos_lockout_notify not in [None, []]
        },
        "user": {
            "roles": list(USER_ROLES),
            "role_dependencies": {k: list(v) for k, v in USER_TYPE_DEP.items()},
            "types": [t for t in USER_TYPES if t != 'custom']
        }
    }
    user_data['indexes'] = list_all_fields(user_data)
    user_data['settings'] = load_user_settings(kwargs['user'])

    msg = UI_MESSAGING.get('system_message')
    if msg:
        user_data['system_message'] = msg

    return make_api_response(user_data)


@user_api.route("/<username>/", methods=["PUT"])
@api_login(require_role=[ROLES.administration])
def add_user_account(username, **_):
    """
    Add a user to the system

    Variables:
    username    => Name of the user to add

    Arguments:
    None

    Data Block:
    {
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",       # Max classification for user
     "uname": "usertest",        # Username
     "type": ['user'],           # List of all types the user is member of
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    }

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """

    data = request.json

    if "{" in username or "}" in username:
        return make_api_response({"success": False}, "You can't use '{}' in the username", 412)

    if not STORAGE.user.get(username):
        new_pass = data.pop('new_pass', None)
        if new_pass:
            password_requirements = config.auth.internal.password_requirements.as_primitives()
            if not check_password_requirements(new_pass, **password_requirements):
                error_msg = get_password_requirement_message(**password_requirements)
                return make_api_response({"success": False}, error_msg, 469)
            data['password'] = get_password_hash(new_pass)
        else:
            data['password'] = data.get('password', "__NO_PASSWORD__") or "__NO_PASSWORD__"

        # Data's username as to match the API call username
        data['uname'] = username
        if not data['name']:
            data['name'] = data['uname']

        # Add add dynamic classification group
        data['classification'] = get_dynamic_classification(data['classification'], data['email'])

        # Clear non user account data
        avatar = data.pop('avatar', None)

        if avatar is not None:
            STORAGE.user_avatar.save(username, avatar)

        try:
            return make_api_response({"success": STORAGE.user.save(username, User(data))})
        except ValueError as e:
            return make_api_response({"success": False}, str(e), 400)

    else:
        return make_api_response({"success": False}, "The username you are trying to add already exists.", 400)


@user_api.route("/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_account(username, **kwargs):
    """
    Load the user account information.

    Variables:
    username       => Name of the user to get the account info

    Arguments:
    load_avatar    => If exists, this will load the avatar as well

    Data Block:
    None

    Result example:
    {
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",            # Max classification for user
     "uname": "usertest",        # Username
     "type": ['user'],           # List of all types the user is member of
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    }
    """
    if username != kwargs['user']['uname'] and 'administration' not in kwargs['user']['roles']:
        return make_api_response({}, "You are not allow to view other users then yourself.", 403)

    user = STORAGE.user.get(username, as_obj=False)
    if not user:
        return make_api_response({}, "User %s does not exists" % username, 404)

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['apikeys'] = list(user.get('apikeys', {}).keys())
    user['has_password'] = user.pop('password', "") != ""
    security_tokens = user.get('security_tokens', {}) or {}
    user['security_tokens'] = list(security_tokens.keys())
    user['security_token_enabled'] = len(security_tokens) != 0

    if "load_avatar" in request.args:
        user['avatar'] = STORAGE.user_avatar.get(username)

    user['roles'] = load_roles(user['type'], user.get('roles', None))

    return make_api_response(user)


@user_api.route("/<username>/", methods=["DELETE"])
@api_login(require_role=[ROLES.administration])
def remove_user_account(username, **_):
    """
    Remove the account specified by the username.

    Variables:
    username       => Name of the user to get the account info

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true  # Was the remove successful?
    }
    """

    user_data = STORAGE.user.get(username)
    if user_data:
        user_deleted = STORAGE.user.delete(username)
        avatar_deleted = STORAGE.user_avatar.delete(username)
        favorites_deleted = STORAGE.user_favorites.delete(username)
        settings_deleted = STORAGE.user_settings.delete(username)

        if not user_deleted or not avatar_deleted or not favorites_deleted or not settings_deleted:
            return make_api_response({"success": False})

        return make_api_response({"success": True})
    else:
        return make_api_response({"success": False},
                                 err=f"User {username} does not exist",
                                 status_code=404)


@user_api.route("/<username>/", methods=["POST"])
@api_login()
def set_user_account(username, **kwargs):
    """
    Save the user account information.

    Variables:
    username    => Name of the user to get the account info

    Arguments:
    None

    Data Block:
    {
     "name": "Test user",        # Name of the user
     "is_active": true,          # Is the user active?
     "classification": "",            # Max classification for user
     "uname": "usertest",        # Username
     "type": ['user'],           # List of all types the user is member of
     "avatar": null,             # Avatar of the user
     "groups": ["TEST"]          # Groups the user is member of
    }

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """
    try:
        data = request.json
        new_pass = data.pop('new_pass', None)

        old_user = STORAGE.user.get(username, as_obj=False)
        if not old_user:
            return make_api_response({"success": False}, "User %s does not exists" % username, 404)

        if not data['name']:
            return make_api_response({"success": False}, "Full name of the user cannot be empty", 400)

        data['apikeys'] = old_user.get('apikeys', [])
        data['otp_sk'] = old_user.get('otp_sk', None)
        data['security_tokens'] = old_user.get('security_tokens', {}) or {}

        if new_pass:
            password_requirements = config.auth.internal.password_requirements.as_primitives()
            if not check_password_requirements(new_pass, **password_requirements):
                error_msg = get_password_requirement_message(**password_requirements)
                return make_api_response({"success": False}, error_msg, 469)
            data['password'] = get_password_hash(new_pass)
            data.pop('new_pass_confirm', None)
        else:
            data['password'] = old_user.get('password', "__NO_PASSWORD__") or "__NO_PASSWORD__"

        # Apply dynamic classification
        data['classification'] = get_dynamic_classification(data['classification'], data['email'])

        ret_val = save_user_account(username, data, kwargs['user'])

        if ret_val and \
                not old_user['is_active'] \
                and data['is_active'] \
                and config.ui.tos_lockout \
                and config.ui.tos_lockout_notify:
            try:
                email = data['email'] or ""
                for adr in config.ui.tos_lockout_notify:
                    send_activated_email(adr, username, email, kwargs['user']['uname'])
                if email:
                    send_activated_email(email, username, email, kwargs['user']['uname'])
            except Exception as e:
                # We can't send confirmation email, Rollback user change and mark this a failure
                STORAGE.user.save(username, old_user)
                LOGGER.error(f"An error occured while sending confirmation emails: {str(e)}")
                return make_api_response({"success": False}, "The system was unable to send confirmation emails. "
                                                             "Retry again later...", 404)

        return make_api_response({"success": ret_val})
    except AccessDeniedException as e:
        return make_api_response({"success": False}, str(e), 403)
    except InvalidDataException as e:
        return make_api_response({"success": False}, str(e), 400)


######################################################
# User's Avatar
######################################################


@user_api.route("/avatar/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_avatar(username, **_):
    """
    Loads the user's avatar.

    Variables:
    username    => Name of the user you want to get the avatar for

    Arguments:
    None

    Data Block:
    None

    Result example:
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD..."
    """
    avatar = STORAGE.user_avatar.get(username)
    if avatar:
        return make_api_response(avatar)
    else:
        return make_api_response(None, "No avatar for specified user", 404)


@user_api.route("/avatar/<username>/", methods=["POST"])
@api_login(audit=False)
def set_user_avatar(username, **kwargs):
    """
    Sets the user's Avatar

    Variables:
    username    => Name of the user you want to set the avatar for

    Arguments:
    None

    Data Block:
    "data:image/jpeg;base64,/9j/4AAQSkZJRgABAQEASABIAAD..."

    Result example:
    {
     "success": true    # Was saving the avatar successful ?
    }
    """
    if username != kwargs['user']['uname']:
        return make_api_response({"success": False}, "Cannot save the avatar of another user.", 403)

    data = request.data
    if data:
        data = data.decode('utf-8')
        if not isinstance(data, str) or not STORAGE.user_avatar.save(username, data):
            make_api_response({"success": False}, "Data block should be a base64 encoded image "
                                                  "that starts with 'data:image/<format>;base64,'", 400)
    else:
        STORAGE.user_avatar.delete(username)
    return make_api_response({"success": True})


######################################################
# User's Favorites
######################################################


@user_api.route("/favorites/<username>/<favorite_type>/", methods=["PUT"])
@api_login(audit=False)
def add_to_user_favorite(username, favorite_type, **kwargs):
    """
    Add an entry to the user's favorites

    Variables:
    username      => Name of the user you want to add a favorite to
    favorite_type => Type of favorite you want to add

    Arguments:
    None

    Data Block:
    {
     "text": "Name of query",
     "query": "*:*"
    }

    Result example:
    { "success": true }
    """
    if favorite_type not in ALLOWED_FAVORITE_TYPE:
        return make_api_response({}, "%s is not a valid favorite type" % favorite_type, 500)

    data = request.json
    data['created_by'] = kwargs['user']['uname']
    if 'name' not in data or 'query' not in data:
        return make_api_response({}, "Wrong format for favorite.", 400)

    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }
    res_favorites = STORAGE.user_favorites.get(username, as_obj=False)
    if res_favorites:
        favorites.update(res_favorites)

    favorites[favorite_type].append(data)

    return make_api_response({"success": STORAGE.user_favorites.save(username, favorites)})


@user_api.route("/favorites/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R'])
def get_user_favorites(username, **kwargs):
    """
    Loads the user's favorites.

    Variables:
    username    => Name of the user you want to get the avatar for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {                   # Dictionary of
     "<name_of_query>":   # Named queries
        "*:*",              # The actual query to run
     ...
    }
    """
    user = kwargs['user']

    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }
    res_favorites = STORAGE.user_favorites.get(username, as_obj=False)

    if res_favorites:
        if username == "__global__" or username != user['uname']:
            for key in favorites.keys():
                for fav in res_favorites[key]:
                    if 'classification' in fav:
                        if CLASSIFICATION.is_accessible(user['classification'], fav['classification']):
                            favorites[key].append(fav)
                    else:
                        favorites[key].append(fav)
        else:
            favorites.update(res_favorites)

    return make_api_response(favorites)


# noinspection PyBroadException
@user_api.route("/favorites/<username>/<favorite_type>/", methods=["DELETE"])
@api_login()
def remove_user_favorite(username, favorite_type, **_):
    """
    Remove a favorite from the user's favorites.

    Variables:
    username       => Name of the user to remove the favorite from
    favorite_type  => Type of favorite to remove

    Arguments:
    None

    Data Block:
    "name_of_favorite"   # Name of the favorite to remove

    Result example:
    {
     "success": true  # Was the remove successful?
    }
    """
    if favorite_type not in ALLOWED_FAVORITE_TYPE:
        return make_api_response({}, "%s is not a valid favorite type" % favorite_type, 500)

    name = request.json
    removed = False
    favorites = STORAGE.user_favorites.get(username, as_obj=False)
    if favorites:
        for fav in favorites[favorite_type]:
            if fav['name'] == name:
                favorites[favorite_type].remove(fav)
                removed = True
                break

    if removed:
        return make_api_response({"success": STORAGE.user_favorites.save(username, favorites)})
    else:
        return make_api_response({}, f"Favorite '{name}' does not exists for {favorite_type} page", 404)


@user_api.route("/favorites/<username>/", methods=["POST"])
@api_login(audit=False)
def set_user_favorites(username, **_):
    """
    Sets the user's Favorites

    Variables:
    username    => Name of the user you want to set the favorites for

    Arguments:
    None

    Data Block:
    {                   # Dictionary of
     "alert": [
               "<name_of_query>":   # Named queries
               "*:*",              # The actual query to run
     ...
    }

    Result example:
    {
     "success": true    # Was saving the favorites successful ?
    }
    """
    data = request.json
    favorites = {
        "alert": [],
        "search": [],
        "signature": [],
        "submission": [],
        "error": []
    }

    for key in data:
        if key not in favorites:
            return make_api_response("", err="Invalid favorite type (%s)" % key, status_code=400)

    favorites.update(data)
    return make_api_response({"success": STORAGE.user_favorites.save(username, data)})


######################################################
# User listing
######################################################


@user_api.route("/list/", methods=["GET"])
@api_login(require_role=[ROLES.administration], audit=False)
def list_users(**_):
    """
    List all users of the system.

    Variables:
    None

    Arguments:
    offset        =>  Offset in the user bucket
    query         =>  Filter to apply to the user list
    rows          =>  Max number of user returned
    sort          =>  Sort order

    Data Block:
    None

    Result example:
    {
     "count": 100,               # Max number of users
     "items": [{                 # List of user blocks
       "name": "Test user",        # Name of the user
       "is_active": true,          # Is the user active?
       "classification": "",            # Max classification for user
       "uname": "usertest",        # Username
       "type": ['user'],           # List of all types the user is member of
       "avatar": null,             # Avatar (Always null here)
       "groups": ["TEST"]          # Groups the user is member of
       }, ...],
     "total": 10,                # Total number of users
     "offset": 0                 # Offset in the user bucket
    }
    """
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*") or "id:*"
    sort = request.args.get('sort', "id asc")

    try:
        return make_api_response(STORAGE.user.search(query, offset=offset, rows=rows, sort=sort, as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


######################################################
# User's settings
######################################################


@user_api.route("/settings/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def get_user_settings(username, **kwargs):
    """
    Load the user's settings.

    Variables:
    username    => Name of the user you want to get the settings for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "profile": true,               # Should submissions be profiled
     "classification": "",          # Default classification for this user sumbissions
     "description": "",             # Default description for this user's submissions
     "download_encoding": "blah",   # Default encoding for downloaded files
     "expand_min_score": 100,       # Default minimum score to auto-expand sections
     "priority": 1000,              # Default submission priority
     "service_spec": [],            # Default Service specific parameters
     "ignore_cache": true,          # Should file be reprocessed even if there are cached results
     "groups": [ ... ],             # Default groups selection for the user scans
     "ttl": 30,                     # Default time to live in days of the users submissions
     "services": [ ... ],           # Default list of selected services
     "ignore_filtering": false      # Should filtering services by ignored?
    }
    """
    user = kwargs['user']

    if username != user['uname']:
        user = STORAGE.user.get(username, as_obj=False)
    return make_api_response(load_user_settings(user))


@user_api.route("/settings/<username>/", methods=["POST"])
@api_login()
def set_user_settings(username, **_):
    """
    Save the user's settings.

    Variables:
    username    => Name of the user you want to set the settings for

    Arguments:
    None

    Data Block:
    {
     "profile": true,                       # Should submissions be profiled
     "classification": "",                  # Default classification for this user sumbissions
     "default_zip_password": "zippy"        # Default password used for protected file downloads
     "description": "",                     # Default description for this user's submissions
     "download_encoding": "blah",           # Default encoding for downloaded files
     "expand_min_score": 100,               # Default minimum score to auto-expand sections
     "priority": 1000,                      # Default submission priority
     "service_spec": [],                    # Default Service specific parameters
     "ignore_cache": true,                  # Should file be reprocessed even if there are cached results
     "groups": [ ... ],                     # Default groups selection for the user scans
     "ttl": 30,                             # Default time to live in days of the users submissions
     "services": [ ... ],                   # Default list of selected services
     "ignore_filtering": false              # Should filtering services by ignored?
    }

    Result example:
    {
     "success"': True              # Was saving the params successful ?
    }
    """
    try:
        data = request.json
        data['service_spec'] = simplify_service_spec(data.get('service_spec', {}))
        if not data.get('default_zip_password', ''):
            return make_api_response({"success": False}, "Encryption password can't be empty.", 403)

        if save_user_settings(username, data):
            return make_api_response({"success": True})
        else:
            return make_api_response({"success": False}, "Failed to save user's settings", 500)
    except ValueError as e:
        return make_api_response({"success": False}, str(e), 400)


######################################################
# User's default submission parameters
######################################################

@user_api.route("/submission_params/<username>/", methods=["GET"])
@api_login(audit=False, required_priv=['R', 'W'])
def get_user_submission_params(username, **kwargs):
    """
    Load the user's default submission params that should be passed to the submit API.
    This is mainly use so you can alter a couple fields and preserve the user
    default values.

    Variables:
    username    => Name of the user you want to get the settings for

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "profile": true,               # Should submissions be profiled
     "classification": "",          # Default classification for this user sumbissions
     "description": "",             # Default description for this user's submissions
     "priority": 1000,              # Default submission priority
     "service_spec": [],            # Default Service specific parameters
     "ignore_cache": true,          # Should file be reprocessed even if there are cached results
     "groups": [ ... ],             # Default groups selection for the user scans
     "ttl": 30,                     # Default time to live in days of the users submissions
     "services": [ ... ],           # Default list of selected services
     "ignore_filtering": false      # Should filtering services by ignored?
    }
    """
    user = kwargs['user']

    if username != "__CURRENT__" and username != user['uname']:
        user = STORAGE.user.get(username, as_obj=False)

    params = load_user_settings(user)
    submission_params = ui_to_submission_params(params)
    submission_params['submitter'] = username
    submission_params['groups'] = user['groups']

    return make_api_response(submission_params)


######################################################
# Terms of service
######################################################

@user_api.route("/tos/<username>/", methods=["GET"])
@api_login()
def agree_with_tos(username, **kwargs):
    """
    Specified user send agreement to Terms of Service

    Variables:
    username    => Name of the user that agrees with tos

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
     "success": true             # Saving the user info succeded
    }
    """
    logged_in_user = kwargs['user']
    if logged_in_user['uname'] != username:
        return make_api_response({"success": False},
                                 "You can't agree to Terms Of Service on behalf of someone else!",
                                 400)

    user = STORAGE.user.get(username)

    if not user:
        return make_api_response({"success": False}, "User %s does not exist." % username, 403)
    else:
        user.agrees_with_tos = now_as_iso()
        if config.ui.tos_lockout:
            user.is_active = False

        if config.ui.tos_lockout and config.ui.tos_lockout_notify:
            # noinspection PyBroadException
            try:
                for adr in config.ui.tos_lockout_notify:
                    send_authorize_email(adr, username, user.email or "")
            except Exception as e:
                LOGGER.error(f"An error occurred while sending confirmation emails: {str(e)}")
                return make_api_response({"success": False}, "The system was unable to send confirmation emails "
                                                             "to the administrators. Retry again later...", 400)

        STORAGE.user.save(username, user)

        return make_api_response({"success": True})
