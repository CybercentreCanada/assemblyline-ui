from typing import Optional

from assemblyline.common.str_utils import safe_str
from assemblyline.odm.models.user import User, load_roles, ROLES
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline_ui.config import LOGGER, STORAGE, SUBMISSION_TRACKER, config, CLASSIFICATION as Classification, \
    SERVICE_LIST
from assemblyline_ui.helper.service import get_default_service_spec, get_default_service_list, simplify_services
from assemblyline_ui.http_exceptions import AccessDeniedException, InvalidDataException, AuthenticationException

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


def check_submission_quota(user) -> Optional[str]:
    quota_user = user['uname']
    max_quota = user.get('submission_quota', 5)

    if config.ui.enforce_quota and not SUBMISSION_TRACKER.begin(quota_user, max_quota):
        LOGGER.info(
            "User %s exceeded their submission quota of %s.",
            quota_user, max_quota
        )
        return "You've exceeded your maximum submission quota of %s " % max_quota
    return None


def decrement_submission_quota(user):
    SUBMISSION_TRACKER.end(user['uname'])


def login(uname, roles_limit):
    user = STORAGE.user.get(uname, as_obj=False)
    if not user:
        raise AuthenticationException("User %s does not exists" % uname)

    if not user['is_active']:
        raise AccessDeniedException("User %s is disabled" % uname)

    add_access_control(user)

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


def save_user_account(username, data, user):
    # Clear non user account data
    avatar = data.pop('avatar', None)
    data.pop('2fa_enabled', None)
    data.pop('security_token_enabled', None)
    data.pop('has_password', None)

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
                         "ttl": config.submission.dtl}).as_primitives()


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
    settings['default_zip_password'] = settings.get('default_zip_password', None)

    # Normalize the user's classification
    settings['classification'] = Classification.normalize_classification(settings['classification'])

    return settings


def save_user_settings(username, data):
    data["services"] = {'selected': simplify_services(data["services"])}

    return STORAGE.user_settings.save(username, data)
