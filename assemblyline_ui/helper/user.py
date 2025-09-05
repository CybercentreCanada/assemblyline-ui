from typing import Optional

from flask import session as flask_session

from assemblyline.common.dict_utils import get_recursive_delta
from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import SubmissionProfile
from assemblyline.odm.models.user import ROLES, User, load_roles
from assemblyline.odm.models.user_settings import (
    DEFAULT_USER_PROFILE_SETTINGS,
    UserSettings,
)
from assemblyline_ui.config import (
    ASYNC_SUBMISSION_TRACKER,
    DAILY_QUOTA_TRACKER,
    DEFAULT_ZIP_PASSWORD,
    DOWNLOAD_ENCODING,
    LOGGER,
    SERVICE_LIST,
    STORAGE,
    SUBMISSION_PROFILES,
    SUBMISSION_TRACKER,
    config,
)
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.helper.service import (
    get_default_service_list,
    get_default_service_spec,
    get_default_submission_profiles,
)
from assemblyline_ui.helper.submission import apply_changes_to_profile
from assemblyline_ui.http_exceptions import (
    AccessDeniedException,
    AuthenticationException,
    InvalidDataException,
)

ACCOUNT_USER_MODIFIABLE = ["name", "avatar", "password"]

API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"],
    "CUSTOM": ["C"]
}

PRIV_API_MAP = {
    "R": "READ",
    "RW": "READ_WRITE",
    "W": "WRITE",
    "C": "CUSTOM",
}

if config.auth.allow_extended_apikeys:
    API_PRIV_MAP["EXTENDED"] = ["R", "W", "E"]
    PRIV_API_MAP['E'] = "EXTENDED"


###########################
# User Functions
def add_access_control(user):
    user.update(Classification.get_access_control_parts(user.get("classification", Classification.UNRESTRICTED),
                                                        user_classification=True))

    gl2_query = " OR ".join(['__access_grp2__:__EMPTY__'] + ['__access_grp2__:"%s"' % x
                                                             for x in user["__access_grp2__"]])
    gl2_query = "(%s) AND " % gl2_query

    gl1_query = " OR ".join(['__access_grp1__:__EMPTY__'] + ['__access_grp1__:"%s"' % x
                                                             for x in user["__access_grp1__"]])
    gl1_query = "(%s) AND " % gl1_query

    req = list(set(Classification.get_access_control_req()).difference(set(user["__access_req__"])))
    req_query = " OR ".join(['__access_req__:"%s"' % r for r in req])
    if req_query:
        req_query = "-(%s) AND " % req_query

    lvl_query = "__access_lvl__:[0 TO %s]" % user["__access_lvl__"]

    query = "".join([gl2_query, gl1_query, req_query, lvl_query])
    user['access_control'] = safe_str(query)


def increase_daily_submission_quota(user) -> Optional[str]:
    if config.ui.enforce_quota:
        quota_user = user['uname']
        daily_quota = user.get('submission_daily_quota')
        if daily_quota is None:
            daily_quota = config.ui.default_quotas.daily_submissions

        if daily_quota != 0:
            current_daily_quota = DAILY_QUOTA_TRACKER.increment_submission(quota_user)
            flask_session['remaining_quota_submission'] = max(daily_quota - current_daily_quota, 0)
            if current_daily_quota > daily_quota:
                LOGGER.info(f"User {quota_user} exceeded their daily submission quota of {daily_quota}.")
                return f"You've exceeded your daily maximum submission quota of {daily_quota}"

    return None


def release_daily_submission_quota(user):
    if config.ui.enforce_quota:
        daily_quota = user.get('submission_daily_quota')
        if daily_quota is None:
            daily_quota = config.ui.default_quotas.daily_submissions

        if daily_quota != 0:
            DAILY_QUOTA_TRACKER.decrement_submission(user['uname'])


def check_async_submission_quota(user) -> Optional[str]:
    if config.ui.enforce_quota:
        quota_user = user['uname']
        max_quota = user.get('submission_async_quota')
        if max_quota is None:
            max_quota = config.ui.default_quotas.concurrent_async_submissions

        daily_submission_quota_error = increase_daily_submission_quota(user)
        if daily_submission_quota_error:
            return daily_submission_quota_error

        if max_quota != 0 and not ASYNC_SUBMISSION_TRACKER.begin(quota_user, max_quota):
            LOGGER.info(f"User {quota_user} exceeded their async submission quota of {max_quota}.")

            # Decrease the daily quota as we have increase it in the increase_daily_submission_quota call
            # but the user is out of concurrent async submission quotas
            release_daily_submission_quota(user)

            return f"You've exceeded your maximum concurrent async submission quota of {max_quota}"

    return None


def check_submission_quota(user) -> Optional[str]:
    if config.ui.enforce_quota:
        quota_user = user['uname']
        max_quota = user.get('submission_quota')
        if max_quota is None:
            max_quota = config.ui.default_quotas.concurrent_submissions

        daily_submission_quota_error = increase_daily_submission_quota(user)
        if daily_submission_quota_error:
            return daily_submission_quota_error

        if max_quota != 0 and not SUBMISSION_TRACKER.begin(quota_user, max_quota):
            LOGGER.info(f"User {quota_user} exceeded their submission quota of {max_quota}.")

            # Decrease the daily quota as we have increase it in the increase_daily_submission_quota call
            # but the user is out of concurrent submission quotas
            release_daily_submission_quota(user)

            return f"You've exceeded your maximum concurrent submission quota of {max_quota}"

    return None


def decrement_submission_ingest_quota(user):
    if config.ui.enforce_quota:
        quota_user = user['uname']
        max_async_quota = user.get('submission_async_quota')
        if max_async_quota is None:
            max_async_quota = config.ui.default_quotas.concurrent_async_submissions

        if max_async_quota != 0:
            ASYNC_SUBMISSION_TRACKER.end(quota_user)

        release_daily_submission_quota(user)


def decrement_submission_quota(user):
    if config.ui.enforce_quota:
        quota_user = user['uname']
        max_quota = user.get('submission_quota')
        if max_quota is None:
            max_quota = config.ui.default_quotas.concurrent_submissions

        if max_quota != 0:
            SUBMISSION_TRACKER.end(quota_user)

        release_daily_submission_quota(user)


def login(uname, roles_limit, user=None):
    apikeys = {}
    if user is None:
        user = STORAGE.user.get(uname, as_obj=False)
        apikeys = get_user_api_keys_dict(uname)

    if not user:
        raise AuthenticationException("User %s does not exists" % uname)

    if not user['is_active']:
        raise AccessDeniedException("User %s is disabled" % uname)

    add_access_control(user)
    get_default_user_quotas(user)

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['apikey_max_dtl'] = config.auth.apikey_max_dtl
    user['allow_2fa'] = config.auth.allow_2fa
    user['allow_apikeys'] = config.auth.allow_apikeys
    user['allow_security_tokens'] = config.auth.allow_security_tokens
    user['apikeys'] = list(apikeys.keys())
    user['c12n_enforcing'] = Classification.enforce
    user['has_password'] = user.pop('password', "") != ""
    user['has_tos'] = config.ui.tos is not None and config.ui.tos != ""
    user['tos_auto_notify'] = config.ui.tos_lockout_notify is not None and config.ui.tos_lockout_notify != []
    user['internal_auth_enabled'] = config.auth.internal.enabled
    security_tokens = user.get('security_tokens', {})
    user['security_tokens'] = list(security_tokens.keys())
    user['security_token_enabled'] = len(security_tokens) != 0
    user['read_only'] = config.ui.read_only
    user['authenticated'] = True
    user['roles'] = [
        r for r in load_roles(user['type'], user.get('roles', None))
        if roles_limit is None or r in roles_limit
    ]

    return user


QUOTA_FIELDS = [
    ('api_quota', config.ui.default_quotas.concurrent_api_calls),
    ('api_daily_quota', config.ui.default_quotas.daily_api_calls),
    ('submission_quota', config.ui.default_quotas.concurrent_submissions),
    ('submission_async_quota', config.ui.default_quotas.concurrent_async_submissions),
    ('submission_daily_quota', config.ui.default_quotas.daily_submissions),
]


def get_default_user_quotas(user_profile: dict):
    for key, default in QUOTA_FIELDS:
        if user_profile.get(key) is None:
            user_profile[key] = default
    return user_profile


def save_user_account(username: str, data: dict, user: dict):
    # Clear non user account data
    avatar = data.pop('avatar', None)
    data.pop('2fa_enabled', None)
    data.pop('security_token_enabled', None)
    data.pop('has_password', None)

    # Verify the user name never changes and that this user is allowed to be modified by the caller
    if username != data['uname']:
        raise AccessDeniedException("You are not allowed to change the username.")
    if username != user['uname'] and ROLES.administration not in user['roles']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    # Get the current data for comparison
    current = STORAGE.user.get(username, as_obj=False)
    if current is None:
        raise InvalidDataException("You cannot save a user that does not exists [%s]." % username)
    current.pop('apikeys', None)  # No longer maintained in this space
    current['roles'] = load_roles(current['type'], current.get('roles', None))

    # The quota defaults get set on profile fetch so we need to handle them separately
    # if no value is set on the database side, don't count the default as an explicit value
    for quota_key, quota_default in QUOTA_FIELDS:
        if current[quota_key] is None:
            if data.get(quota_key, quota_default) == quota_default:
                data.pop(quota_key)
                continue

    # Normalize all other fields of the new data
    data = User(data).as_primitives()

    # Non-admin users are only allowed to modify some fields
    if ROLES.administration not in user['roles']:
        # identity_id is wiped on data sent to non-admins so needs to be restored here
        data['identity_id'] = current['identity_id']

        # Check all other fields
        for key in current.keys():
            if data[key] != current[key] and key not in ACCOUNT_USER_MODIFIABLE:
                LOGGER.warning('%s tried to modify setting %s: %s -> %s', username, key, current[key], data[key])
                raise AccessDeniedException("Only Administrators can change the value of the field [%s]." % key)

    if avatar is None:
        STORAGE.user_avatar.delete(username)
    else:
        STORAGE.user_avatar.save(username, avatar)

    return STORAGE.user.save(username, data)


def get_dynamic_classification(current_c12n, user_info):
    new_c12n = Classification.normalize_classification(
        current_c12n, skip_auto_select=True, get_dynamic_groups=False, ignore_unused=True)

    if Classification.dynamic_groups:
        email = user_info.get('email', None)
        groups = user_info.get('groups', [])

        if Classification.dynamic_groups_type in ['email', 'all'] and email:
            dyn_group = email.upper().split('@')[1]
            new_c12n = Classification.build_user_classification(
                new_c12n, f"{Classification.UNRESTRICTED}//REL {dyn_group}")

        if Classification.dynamic_groups_type in ['group', 'all'] and groups:
            new_c12n = Classification.build_user_classification(
                new_c12n, f"{Classification.UNRESTRICTED}//REL {', '.join(groups)}")

    return new_c12n


def get_default_user_settings(user: dict) -> dict:
    settings = DEFAULT_USER_PROFILE_SETTINGS
    settings.update({"default_zip_password": DEFAULT_ZIP_PASSWORD, "download_encoding": DOWNLOAD_ENCODING})
    return UserSettings(settings).as_primitives()

def get_user_api_keys_dict(uname):
    apikeys = get_user_api_keys(uname)
    apikeys_dict = dict((apikey['key_name'], apikey) for apikey in apikeys)
    return apikeys_dict

def get_user_api_keys(uname):
    apikeys = STORAGE.apikey.stream_search(f"uname:{uname}", as_obj=False)
    return apikeys

def load_user_settings(user):
    default_settings = get_default_user_settings(user)
    user_classfication = user.get('classification', Classification.UNRESTRICTED)
    submission_customize = ROLES.submission_customize in user['roles']
    settings = STORAGE.user_settings.get_if_exists(user['uname'])
    if not settings:
        settings = default_settings
    else:
        settings = settings.as_primitives(strip_null=True)
        # Make sure all defaults are there
        for key, item in default_settings.items():
            if key not in settings:
                settings[key] = item

        # Remove all obsolete keys
        for key in list(settings.keys()):
            if key not in default_settings:
                del settings[key]

    srv_list = [x for x in SERVICE_LIST if x['enabled']]
    settings['default_zip_password'] = settings.get('default_zip_password', DEFAULT_ZIP_PASSWORD)

    # Omit the use of the default profile if the user is not allowed to customize their submission
    if not submission_customize:
        settings['submission_profiles'].pop("default", None)
    else:
        settings['submission_profiles'].setdefault("default", {})

    # Only display services that a user is allowed to see
    settings['service_spec'] = get_default_service_spec(srv_list, user_classfication)
    settings['services'] = get_default_service_list(srv_list, user_classfication)
    settings['submission_profiles'] = get_default_submission_profiles(settings['submission_profiles'],
                                                                      user_classfication)


    # Check if the user has a preferred submission profile
    if not settings.get('preferred_submission_profile'):
        # No preferred submission profile, set one based on the user's roles
        if submission_customize:
            # User can customize their submission, set the preferred profile to the legacy default
            settings['preferred_submission_profile'] = 'default'
        else:
            # User cannot customize their submission, set the preferred profile to first one on the list
            settings['preferred_submission_profile'] = list(settings['submission_profiles'].keys())[0]

    return settings


def save_user_settings(user, data):
    username = user.get('uname', None)
    if not username:
        raise Exception("No username provided to save user settings")

    user_settings = STORAGE.user_settings.get(username, as_obj=False) or {}

    classification = user.get("classification", None)
    accessible_profiles = [name for name, profile in SUBMISSION_PROFILES.items() \
                           if Classification.is_accessible(classification, profile.classification)]

    # Check for any changes to settings that aren't submission-related
    user_settings.update({k: data[k] for k in UserSettings.fields().keys()
                          if k not in ['submission_profiles', 'preferred_submission_profile'] and k in data})

    # Check submission profile preference selection
    preferred_submission_profile = data.get('preferred_submission_profile', None)
    if ROLES.submission_customize in user['roles']:
        # User is allowed to customize their own default profile
        accessible_profiles += ['default']

    if preferred_submission_profile in accessible_profiles:
        # Update the preferred submission profile
        user_settings['preferred_submission_profile'] = preferred_submission_profile

    submission_profiles = {}
    for name in accessible_profiles:
        user_params = data.get('submission_profiles', {}).get(name, {})
        profile_config: Optional[SubmissionProfile] = SUBMISSION_PROFILES.get(name)

        if not profile_config:
            if name == "default" and user_params:
                # There is no restriction on what you can set for your default submission profile
                submission_profiles[name] = user_params
        else:
            # Calculate what the profiles updates are based on default profile settings and the user-submitted changes
            profile_updates = get_recursive_delta(DEFAULT_USER_PROFILE_SETTINGS, user_params)

            # Apply changes to the profile relative to what's allowed to be changed based on configuration
            submission_profiles[name] = apply_changes_to_profile(profile_config, profile_updates, user)

    user_settings["submission_profiles"] = submission_profiles

    return STORAGE.user_settings.save(username, user_settings)