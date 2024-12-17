from typing import Optional

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.config import SubmissionProfileParams
from assemblyline.odm.models.user import ROLES, User, load_roles
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline_ui.config import ASYNC_SUBMISSION_TRACKER
from assemblyline_ui.config import CLASSIFICATION as Classification
from assemblyline_ui.config import (
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
from assemblyline_ui.helper.service import (
    get_default_service_list,
    get_default_service_spec,
    get_default_submission_profiles,
    simplify_services,
)
from assemblyline_ui.http_exceptions import AccessDeniedException, AuthenticationException, InvalidDataException
from flask import session as flsk_session

ACCOUNT_USER_MODIFIABLE = ["name", "avatar", "password"]

API_PRIV_MAP = {
    "READ": ["R"],
    "READ_WRITE": ["R", "W"],
    "WRITE": ["W"],
    "CUSTOM": ["C"]
}

if config.auth.allow_extended_apikeys:
    API_PRIV_MAP["EXTENDED"] = ["R", "W", "E"]


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
            flsk_session['remaining_quota_submission'] = max(daily_quota - current_daily_quota, 0)
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
    if user is None:
        user = STORAGE.user.get(uname, as_obj=False)

    if not user:
        raise AuthenticationException("User %s does not exists" % uname)

    if not user['is_active']:
        raise AccessDeniedException("User %s is disabled" % uname)

    add_access_control(user)
    get_default_user_quotas(user)

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['allow_2fa'] = config.auth.allow_2fa
    user['allow_apikeys'] = config.auth.allow_apikeys
    user['allow_security_tokens'] = config.auth.allow_security_tokens
    user['apikeys'] = list(user.get('apikeys', {}).keys())
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


def get_default_user_quotas(user_profile: dict):
    if user_profile.get('api_quota') is None:
        user_profile['api_quota'] = config.ui.default_quotas.concurrent_api_calls

    if user_profile.get('api_daily_quota') is None:
        user_profile['api_daily_quota'] = config.ui.default_quotas.daily_api_calls

    if user_profile.get('submission_quota') is None:
        user_profile['submission_quota'] = config.ui.default_quotas.concurrent_submissions

    if user_profile.get('submission_async_quota') is None:
        user_profile['submission_async_quota'] = config.ui.default_quotas.concurrent_async_submissions

    if user_profile.get('submission_daily_quota') is None:
        user_profile['submission_daily_quota'] = config.ui.default_quotas.daily_submissions

    return user_profile


def save_user_account(username, data, user):
    # Clear non user account data
    avatar = data.pop('avatar', None)
    data.pop('2fa_enabled', None)
    data.pop('security_token_enabled', None)
    data.pop('has_password', None)

    # Make sure the default quotas are set
    get_default_user_quotas(data)

    # Test the user params againts the model
    data = User(data).as_primitives()

    if username != data['uname']:
        raise AccessDeniedException("You are not allowed to change the username.")

    if username != user['uname'] and ROLES.administration not in user['roles']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    current = STORAGE.user.get(username, as_obj=False)
    if current:
        if ROLES.administration not in user['roles']:
            for key in current.keys():
                if data[key] != current[key] and key not in ACCOUNT_USER_MODIFIABLE:
                    raise AccessDeniedException("Only Administrators can change the value of the field [%s]." % key)
    else:
        raise InvalidDataException("You cannot save a user that does not exists [%s]." % username)

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


def get_default_user_settings(user):
    return UserSettings({"classification": Classification.default_user_classification(user),
                         "ttl": config.submission.dtl,
                         "default_zip_password": DEFAULT_ZIP_PASSWORD,
                         "download_encoding": DOWNLOAD_ENCODING}).as_primitives()


def load_user_settings(user):
    default_settings = get_default_user_settings(user)
    user_classfication = user.get('classification', Classification.UNRESTRICTED)

    settings = STORAGE.user_settings.get_if_exists(user['uname'], as_obj=False)
    srv_list = [x for x in SERVICE_LIST if x['enabled']]
    if not settings:
        def_srv_list = None
        settings = default_settings
    else:
        # Make sure all defaults are there
        for key, item in default_settings.items():
            if key not in settings:
                settings[key] = item

        # Remove all obsolete keys
        for key in list(settings.keys()):
            if key not in default_settings:
                del settings[key]

        def_srv_list = settings.get('services', {}).get('selected', None)

    # Only display services that a user is allowed to see
    settings['service_spec'] = get_default_service_spec(srv_list, settings.get('service_spec', {}), user_classfication)
    settings['services'] = get_default_service_list(srv_list, def_srv_list, user_classfication)
    settings['submission_profiles'] = get_default_submission_profiles(settings['submission_profiles'],
                                                                      user_classfication)
    settings['default_zip_password'] = settings.get('default_zip_password', DEFAULT_ZIP_PASSWORD)

    # Normalize the user's classification
    settings['classification'] = Classification.normalize_classification(settings['classification'])

    if settings.get('preferred_submission_profile', None) not in list(settings['submission_profiles'].keys()):
        settings['preferred_submission_profile'] = list(settings['submission_profiles'].keys())[0]

    return settings


def save_user_settings(user, data):
    username = user.get('uname', None)
    if username == None:
        raise Exception("Invalid username")

    out = STORAGE.user_settings.get(username).as_primitives()
    for key in out.keys():
        if key in data and key not in ["services", "service_spec", "submission_profiles"]:
            out[key] = data.get(key, None)

    out["services"] = {'selected': simplify_services(data["services"])}

    classification = user.get("classification", None)
    submission_customize = ROLES.submission_customize in user['roles']
    srv_list = [x['name'] for x in SERVICE_LIST if x['enabled']]
    srv_list += [x['category'] for x in SERVICE_LIST if x['enabled']]
    srv_list = list(set(srv_list))

    if data.get('preferred_submission_profile', None) not in SUBMISSION_PROFILES.keys():
        out['preferred_submission_profile'] = SUBMISSION_PROFILES.keys()[0]
    else:
        out['preferred_submission_profile'] = data['preferred_submission_profile']

    submission_profiles = {}
    for name, profile in SUBMISSION_PROFILES.items():
        if Classification.is_accessible(classification, profile.classification):
            user_params = data.get('submission_profiles', {}).get(profile.name, {}).get('params', {})

            # Applying the submission params
            profile_defaults = SubmissionProfileParams().as_primitives()
            default_keys = profile["editable_params"].get("submit", [])
            for key in profile_defaults.keys():
                if key in user_params and key not in ["services", "service_spec"] and \
                        (submission_customize or key in default_keys):
                    profile["params"][key] = user_params.get(key, None)

            # Applying the selected services
            if submission_customize:
                profile["params"]["services"]["selected"] = [x for x in user_params.get(
                    'services', {}).get('selected', []) if x in srv_list]

            # Applying the service specs
            profile["params"]["service_spec"] = {}
            for svr_name, spec in user_params.get("service_spec", {}).items():
                for p_name, p_value in spec.items():
                    if (p_name in profile["editable_params"].get(svr_name, []) or submission_customize) and \
                            svr_name in srv_list:
                        profile["params"]["service_spec"].setdefault(svr_name, {}).setdefault(p_name, p_value)

            submission_profiles[name] = profile.params.as_primitives(strip_null=True)

    out["submission_profiles"] = submission_profiles

    return STORAGE.user_settings.save(username, out)
