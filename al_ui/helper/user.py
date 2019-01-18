
from assemblyline.common.str_utils import safe_str
from assemblyline.common import forge
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_options import UserOptions
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

        if not config.ui.get('read_only'):
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
            if config.logging.logserver.kibana.host:
                user["kibana_dashboards"] = [{"icon": None,
                                              "active": path.startswith("/kibana-dash.html?dash=%s" % x),
                                              "link": "/kibana-dash.html?dash=%s" % x,
                                              "title": "%s" % x.replace("-", " ")}
                                             for x in config.logging.logserver.kibana.dashboards if x != ""]
            user["admin_menu"] = [{"icon": None, "active": path.startswith("/admin/seed.html"),
                                   "link": "/admin/seed.html", "title": "Configuration"},
                                  {"icon": None, "active": path.startswith("/admin/documentation.html"),
                                   "link": "/admin/documentation.html", "title": "Documentation"},
                                  {"icon": None, "active": path.startswith("/admin/errors.html"),
                                   "link": "/admin/errors.html", "title": "Errors viewer"}]
            if not config.ui.get('read_only'):
                user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/hosts.html"),
                                            "link": "/admin/hosts.html", "title": "Hosts"},
                                           {"icon": None, "active": path.startswith("/admin/services.html"),
                                            "link": "/admin/services.html", "title": "Services"}])
            user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/site_map.html"),
                                        "link": "/admin/site_map.html", "title": "Site Map"},
                                       {"icon": None, "active": path.startswith("/admin/users.html"),
                                        "link": "/admin/users.html", "title": "Users"}])
            if not config.ui.get('read_only'):
                user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/virtual_machines.html"),
                                            "link": "/admin/virtual_machines.html", "title": "Virtual Machines"}])
        else:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/dashboard.html"))
            user["kibana_dashboards"] = []
            user["admin_menu"] = []

    user['2fa_enabled'] = user.pop('otp_sk', "") != ""
    user['allow_2fa'] = config.auth.allow_2fa
    user['allow_apikeys'] = config.auth.allow_apikeys
    user['allow_u2f'] = config.auth.allow_u2f
    user['apikeys'] = [x['name'] for x in user['apikeys']]
    user['c12n_enforcing'] = CLASSIFICATION.enforce
    user['has_password'] = user.pop('password', "") != ""
    user['internal_auth_enabled'] = config.auth.internal.enabled
    u2f_devices = user.get('u2f_devices', {})
    if isinstance(u2f_devices, list):
        u2f_devices = {"default": d for d in u2f_devices}
    user['u2f_devices'] = u2f_devices.keys()
    user['u2f_enabled'] = len(u2f_devices) != 0
    user['read_only'] = config.ui.read_only
    user['authenticated'] = True

    return user


def save_user_account(username, data, user):
    # TODO: Not sure how that works now with the models...
    # data = validate_settings(data, ACCOUNT_DEFAULT, exceptions=['avatar', 'agrees_with_tos',
    #                                                             'dn', 'password', 'otp_sk', 'u2f_devices'])
    data = User(data)

    if username != data['uname']:
        raise AccessDeniedException("You are not allowed to change the username.")

    if username != user['uname'] and not user['is_admin']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    current = STORAGE.get_user_account(username)
    if current:
        # TODO: Not sure how that works now with the models...
        # current = validate_settings(current, ACCOUNT_DEFAULT,
        #                                     exceptions=['avatar', 'agrees_with_tos',
        #                                                 'dn', 'password', 'otp_sk', 'u2f_devices'])
        current = User(current)
        
        if not user['is_admin']:
            for key in current.iterkeys():
                if data[key] != current[key] and key not in ACCOUNT_USER_MODIFIABLE:
                    raise AccessDeniedException("Only Administrators can change the value of the field [%s]." % key)
    else:
        raise InvalidDataException("You cannot save a user that does not exists [%s]." % username)

    if not data['avatar']:
        STORAGE.delete_user(data['uname'] + "_avatar")
    else:
        STORAGE.set_user_avatar(username, data['avatar'])
    data['avatar'] = None
        
    return STORAGE.set_user_account(username, data)


def get_default_user_settings(user):
    # TODO: Not sure how that works now with the models...
    # out = copy.deepcopy(SETTINGS_DEFAULT)
    out = UserOptions()

    out['classification'] = Classification.default_user_classification(user)
    out['services'] = ["Extraction", "Static Analysis", "Filtering", "Antivirus", "Post-Processing"]
    return out


def load_user_settings(user):
    default_settings = UserOptions({
        "classification": Classification.default_user_classification(user)}).as_primitives()

    options = STORAGE.user_options.get(user['uname'], as_obj=False)
    srv_list = [x for x in STORAGE.list_services(as_obj=False) if x['enabled']]
    if not options:
        def_srv_list = None
        options = default_settings
    else:
        # Make sure all defaults are there
        for key, item in default_settings.items():
            if key not in options:
                options[key] = item
        
        # Remove all obsolete keys
        for key in options.keys():
            if key not in default_settings:
                del options[key]
                
        def_srv_list = options.get('services', None)
    
    options['service_spec'] = get_default_service_spec(srv_list)
    options['services'] = get_default_service_list(srv_list, def_srv_list)

    # Normalize the user's classification
    options['classification'] = Classification.normalize_classification(options['classification'])

    return options


# noinspection PyBroadException
def remove_ui_specific_options(task):
    # Cleanup task object
    task.pop('download_encoding', None)
    task.pop('expand_min_score', None)
    task.pop('hide_raw_results', None)
    task.pop('service_spec', None)
    task.pop('services', None)

    return task


def save_user_settings(username, data):
    data["service_spec"] = {}
    data["services"] = simplify_services(data["services"])
    
    return STORAGE.user_options.save(username, data)


def validate_settings(data, defaults, exceptions=None):
    if not exceptions:
        exceptions = []

    for key in defaults.iterkeys():
        if key not in data:
            data[key] = defaults[key]
        else:
            if key not in exceptions \
                    and not (isinstance(data[key], str) and isinstance(defaults[key], str)) \
                    and not isinstance(data[key], type(defaults[key])):
                raise Exception("Wrong data type for parameter [%s]" % key)
            else:
                item = data[key]
                if key == 'u2f_devices':
                    continue

                if isinstance(item, str):
                    data[key] = item.replace("{", "").replace("}", "")
                elif isinstance(item, list):
                    if len(item) > 0 and isinstance(item[0], str):
                        data[key] = [i.replace("{", "").replace("}", "") for i in item]

    to_del = []
    for key in data.iterkeys():
        if key not in defaults:
            to_del.append(key)
            
    for key in to_del:
        del(data[key])
        
    return data
