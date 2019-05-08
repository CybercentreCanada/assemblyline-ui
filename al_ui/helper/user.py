
from assemblyline.common.str_utils import safe_str
from assemblyline.common import forge
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline.remote.datatypes.hash import Hash
from al_ui.config import LOGGER, STORAGE, CLASSIFICATION
from al_ui.helper.service import get_default_service_spec, get_default_service_list, simplify_services
from al_ui.http_exceptions import AccessDeniedException, InvalidDataException, QuotaExceededException

ACCOUNT_USER_MODIFIABLE = ["name", "avatar", "groups", "password"]
config = forge.get_config()
Classification = forge.get_classification()

persistent = {
    'db': config.core.redis.persistent.db,
    'host': config.core.redis.persistent.host,
    'port': config.core.redis.persistent.port,
}


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
     

def check_submission_quota(user, num=1):
    quota_user = user['uname']
    quota = user.get('submission_quota', 5)
    count = num + Hash('submissions-' + quota_user, **persistent).length()
    if count > quota:
        LOGGER.info(
            "User %s exceeded their submission quota. [%s/%s]",
            quota_user, count, quota
        )
        raise QuotaExceededException("You've exceeded your maximum submission quota of %s " % quota)
        

def login(uname, path=None):
    user = STORAGE.user.get(uname, as_obj=False)
    if not user:
        raise AccessDeniedException("User %s does not exists" % uname)
    
    if not user['is_active']:
        raise AccessDeniedException("User %s is disabled" % uname)
    
    add_access_control(user)
    
    if path:
        user["submenu"] = [{"icon": "glyphicon-user", "active": path.startswith("/account.html"),
                            "link": "/account.html", "title": "Account"}]

        if not config.ui.read_only:
            user["submenu"].extend(
                [{"icon": "glyphicon-tasks", "active": path.startswith("/dashboard.html"),
                  "link": "/dashboard.html", "title": "Dashboard"}])

        user["submenu"].extend([{"icon": "glyphicon-cog", "active": path.startswith("/settings.html"),
                                 "link": "/settings.html", "title": "Settings"},
                                {"icon": "glyphicon-log-out", "active": path.startswith("/logout.html"),
                                 "link": "/logout.html", "title": "Sign out"}])

        if user['is_admin']:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/admin/") or path.startswith("/dashboard.html") or
                                   path.startswith("/kibana-dash.html"))
            # TODO: Maybe we should remove this from our interface. I'm excluding it for now
            # if config.logging.logserver.kibana.host:
            #     user["kibana_dashboards"] = [{"icon": None,
            #                                   "active": path.startswith("/kibana-dash.html?dash=%s" % x),
            #                                   "link": "/kibana-dash.html?dash=%s" % x,
            #                                   "title": "%s" % x.replace("-", " ")}
            #                                  for x in config.logging.logserver.kibana.dashboards if x != ""]
            user["admin_menu"] = [{"icon": None, "active": path.startswith("/admin/seed.html"),
                                   "link": "/admin/seed.html", "title": "Configuration"},
                                  {"icon": None, "active": path.startswith("/admin/documentation.html"),
                                   "link": "/admin/documentation.html", "title": "Documentation"},
                                  {"icon": None, "active": path.startswith("/admin/errors.html"),
                                   "link": "/admin/errors.html", "title": "Errors viewer"}]
            if not config.ui.read_only:
                user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/hosts.html"),
                                            "link": "/admin/hosts.html", "title": "Hosts"},
                                           {"icon": None, "active": path.startswith("/admin/services.html"),
                                            "link": "/admin/services.html", "title": "Services"}])
            user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/site_map.html"),
                                        "link": "/admin/site_map.html", "title": "Site Map"},
                                       {"icon": None, "active": path.startswith("/admin/users.html"),
                                        "link": "/admin/users.html", "title": "Users"}])
            if not config.ui.read_only:
                user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/virtual_machines.html"),
                                            "link": "/admin/virtual_machines.html", "title": "Virtual Machines"}])
        else:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/dashboard.html"))
            user["kibana_dashboards"] = []
            user["admin_menu"] = []

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['allow_2fa'] = config.auth.allow_2fa
    user['allow_apikeys'] = config.auth.allow_apikeys
    user['allow_u2f'] = config.auth.allow_u2f
    user['apikeys'] = list(user.get('apikeys', {}).keys())
    user['c12n_enforcing'] = CLASSIFICATION.enforce
    user['has_password'] = user.pop('password', "") != ""
    user['internal_auth_enabled'] = config.auth.internal.enabled
    u2f_devices = user.get('u2f_devices', {})
    user['u2f_devices'] = list(u2f_devices.keys())
    user['u2f_enabled'] = len(u2f_devices) != 0
    user['read_only'] = config.ui.read_only
    user['authenticated'] = True

    return user


def save_user_account(username, data, user):
    # Clear non user account data
    avatar = data.pop('avatar', None)
    data.pop('2fa_enabled', None)
    data.pop('u2f_enabled', None)
    data.pop('has_password', None)

    data = User(data).as_primitives()

    if username != data['uname']:
        raise AccessDeniedException("You are not allowed to change the username.")

    if username != user['uname'] and not user['is_admin']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    current = STORAGE.user.get(username, as_obj=False)
    if current:
        if not user['is_admin']:
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


def get_default_user_settings(user):
    return UserSettings({"classification": Classification.default_user_classification(user)}).as_primitives()


def load_user_settings(user):
    default_settings = get_default_user_settings(user)

    settings = STORAGE.user_settings.get(user['uname'], as_obj=False)
    srv_list = [x for x in STORAGE.list_all_services(as_obj=False, full=True) if x['enabled']]
    if not settings:
        def_srv_list = None
        settings = default_settings
    else:
        # Make sure all defaults are there
        for key, item in default_settings.items():
            if key not in settings:
                settings[key] = item
        
        # Remove all obsolete keys
        for key in settings.keys():
            if key not in default_settings:
                del settings[key]
                
        def_srv_list = settings.get('services', {}).get('selected', None)
    
    settings['service_spec'] = get_default_service_spec(srv_list)
    settings['services'] = get_default_service_list(srv_list, def_srv_list)

    # Normalize the user's classification
    settings['classification'] = Classification.normalize_classification(settings['classification'])

    return settings


def save_user_settings(username, data):
    data["service_spec"] = {}
    data["services"] = {'selected': simplify_services(data["services"])}
    
    return STORAGE.user_settings.save(username, data)
