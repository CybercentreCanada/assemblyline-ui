from typing import Optional

from assemblyline.common.str_utils import safe_str
from assemblyline.common import forge
from assemblyline.odm.models.user import User
from assemblyline.odm.models.user_settings import UserSettings
from assemblyline_ui.config import LOGGER, STORAGE, CLASSIFICATION, SUBMISSION_TRACKER
from assemblyline_ui.helper.service import get_default_service_spec, get_default_service_list, simplify_services
from assemblyline_ui.http_exceptions import AccessDeniedException, InvalidDataException, AuthenticationException

ACCOUNT_USER_MODIFIABLE = ["name", "avatar", "groups", "password"]
config = forge.get_config()
Classification = forge.get_classification()


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

    if not SUBMISSION_TRACKER.begin(quota_user, max_quota):
        LOGGER.info(
            "User %s exceeded their submission quota of %s.",
            quota_user, max_quota
        )
        return "You've exceeded your maximum submission quota of %s " % max_quota
    return None


def decrement_submission_quota(user):
    SUBMISSION_TRACKER.end(user['uname'])


def create_menu(user, path):
    user['groups'].insert(0, "ALL")

    submission_submenu = [{"class": "dropdown-header",
                           "active": False,
                           "link": None,
                           "title": "Personal"},
                          {"class": "",
                           "active": (path == "/submissions.html?user=%s" % user['uname']),
                           "link": "/submissions.html?user=%s" % user['uname'],
                           "title": "My Submissions"},
                          {"class": "divider",
                           "active": False,
                           "link": None,
                           "title": None},
                          {"class": "dropdown-header",
                           "active": False,
                           "link": None,
                           "title": "Groups"}]

    submission_submenu.extend([{"class": "",
                                "active": (path == "/submissions.html?group=%s" % x),
                                "link": "/submissions.html?group=%s" % x,
                                "title": x} for x in user['groups']])

    help_submenu = [{"class": "dropdown-header",
                     "active": False,
                     "link": None,
                     "title": "Documentation"},
                    {"class": "",
                     "active": path.startswith("/api_doc.html"),
                     "link": "/api_doc.html",
                     "title": "API Documentation"}]

    if forge.get_classification().enforce:
        help_submenu.extend([{"class": "",
                              "active": path.startswith("/classification_help.html"),
                              "link": "/classification_help.html",
                              "title": "Classification Help"}])

    if not config.ui.read_only:
        help_submenu.extend([{"class": "",
                              "active": path.startswith("/configuration.html"),
                              "link": "/configuration.html",
                              "title": "Configuration Settings"}])

    help_submenu.extend([
        {"class": "",
         "active": path.startswith("/search_help.html"),
         "link": "/search_help.html",
         "title": "Search Help"}])

    if not config.ui.read_only:
        help_submenu.extend([
            {"class": "",
             "active": path.startswith("/services.html"),
             "link": "/services.html",
             "title": "Service Listing"},
            {"class": "divider",
             "active": False,
             "link": None,
             "title": None},
            {"class": "dropdown-header",
             "active": False,
             "link": None,
             "title": "Heuristics"},
            {"class": "",
             "active": path.startswith("/heuristics.html"),
             "link": "/heuristics.html",
             "title": "Malware Heuristics"},
            {"class": "divider",
             "active": False,
             "link": None,
             "title": None},
            {"class": "dropdown-header",
             "active": False,
             "link": None,
             "title": "Statistics"},
            {"class": "",
             "active": path.startswith("/heuristics_stats.html"),
             "link": "/heuristics_stats.html",
             "title": "Heuristic Statistics"},
            {"class": "",
             "active": path.startswith("/signature_statistics.html"),
             "link": "/signature_statistics.html",
             "title": "Signature Statistics"}
        ])

    alerting_submenu = [
        {"class": "",
         "active": path.startswith("/alerts.html"),
         "link": "/alerts.html",
         "title": "View Alerts",
         "has_submenu": False},
        {"class": "",
         "active": path.startswith("/workflows.html"),
         "link": "/workflows.html",
         "title": "Workflow filters",
         "has_submenu": False}
    ]

    menu = [{"class": "",
             "active": path.split("?")[0] == "/" or path.startswith("/submit.html"),
             "link": "/submit.html",
             "title": "Submit",
             "has_submenu": False},
            {"class": "",
             "active": path.startswith("/submissions.html"),
             "link": "#",
             "title": "Submissions",
             "has_submenu": True,
             "submenu": submission_submenu},
            {"class": "",
             "active": path.startswith("/alerts.html") or path.startswith("/workflows.html"),
             "link": "#",
             "title": "Alerts",
             "has_submenu": True,
             "submenu": alerting_submenu}]

    if not config.ui.read_only:
        if 'admin' in user['type'] or 'signature_manager' in user['type']:
            signature_submenu = [
                {"class": "",
                 "active": path.startswith("/signatures.html"),
                 "link": "/signatures.html",
                 "title": "Signature management",
                 "has_submenu": False},
                {"class": "",
                 "active": path.startswith("/source_management.html"),
                 "link": "/source_management.html",
                 "title": "Source management",
                 "has_submenu": False}
            ]

            menu.append({"class": "",
                         "active": path.startswith("/signatures.html") or path.startswith("/source_management.html"),
                         "link": "#",
                         "title": "Signatures",
                         "has_submenu": True,
                         "submenu": signature_submenu})
        else:
            menu.append({"class": "",
                         "active": path.startswith("/signatures.html"),
                         "link": "/signatures.html",
                         "title": "Signatures",
                         "has_submenu": False})

    search_submenu = [
        {"class": "",
         "active": path.startswith("/search.html") and ("search_scope=all" in path or "search_scope" not in path),
         "link": "/search.html",
         "title": "All indexes",
         "has_submenu": False},
        {"class": "divider",
         "active": False,
         "link": None,
         "title": None},
        {"class": "dropdown-header",
         "active": False,
         "link": None,
         "title": "Specific indexes"},

    ]

    for idx in ["Alert", "File", "Result", "Signature", "Submission"]:
        search_submenu.append({"class": "",
                               "active": path.startswith("/search.html") and f"search_scope={idx.lower()}" in path,
                               "link": f"/search.html?search_scope={idx.lower()}",
                               "title": f"{idx} Index",
                               "has_submenu": False})

    menu.extend([
        {"class": "",
         "active": path.startswith("/search.html"),
         "link": "/search.html",
         "title": "Search",
         "has_submenu": True,
         "submenu": search_submenu},
        {"class": "",
         "active": path.startswith("/api_doc.html") or
            path.startswith("/classification_help.html") or
            path.startswith("/configuration.html") or
            path.startswith("/heuristics.html") or
            path.startswith("/heuristics_stats.html") or
            path.startswith("/signature_statistics.html") or
            path.startswith("/search_help.html") or
            path.startswith("/services.html"),
         "link": "#",
         "title": "Help",
         "has_submenu": True,
         "submenu": help_submenu}])

    return menu


def login(uname, path=None):
    user = STORAGE.user.get(uname, as_obj=False)
    if not user:
        raise AuthenticationException("User %s does not exists" % uname)
    
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

        if 'admin' in user['type']:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/admin/") or path.startswith("/dashboard.html") or
                                   path.startswith("/kibana-dash.html"))
            user["admin_menu"] = [
                {"icon": None, "active": path.startswith("/admin/errors.html"),
                 "link": "/admin/errors.html", "title": "Errors viewer"}]
            if not config.ui.read_only:
                user["admin_menu"].extend([
                    {"icon": None, "active": path.startswith("/admin/services.html"),
                     "link": "/admin/services.html", "title": "Services"}])
            user["admin_menu"].extend([{"icon": None, "active": path.startswith("/admin/site_map.html"),
                                        "link": "/admin/site_map.html", "title": "Site Map"},
                                       {"icon": None, "active": path.startswith("/admin/users.html"),
                                        "link": "/admin/users.html", "title": "Users"}])
        else:
            user['menu_active'] = (path.startswith("/settings.html") or path.startswith("/account.html") or
                                   path.startswith("/dashboard.html"))
            user["kibana_dashboards"] = []
            user["admin_menu"] = []

    user['2fa_enabled'] = user.pop('otp_sk', None) is not None
    user['allow_2fa'] = config.auth.allow_2fa
    user['allow_apikeys'] = config.auth.allow_apikeys
    user['allow_security_tokens'] = config.auth.allow_security_tokens
    user['apikeys'] = list(user.get('apikeys', {}).keys())
    user['c12n_enforcing'] = CLASSIFICATION.enforce
    user['has_password'] = user.pop('password', "") != ""
    user['has_tos'] = config.ui.tos is not None and config.ui.tos != ""
    user['tos_auto_notify'] = config.ui.tos_lockout_notify is not None and config.ui.tos_lockout_notify != []
    user['internal_auth_enabled'] = config.auth.internal.enabled
    security_tokens = user.get('security_tokens', {})
    user['security_tokens'] = list(security_tokens.keys())
    user['security_token_enabled'] = len(security_tokens) != 0
    user['read_only'] = config.ui.read_only
    user['authenticated'] = True

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

    if username != user['uname'] and 'admin' not in user['type']:
        raise AccessDeniedException("You are not allowed to change another user then yourself.")

    current = STORAGE.user.get(username, as_obj=False)
    if current:
        if 'admin' not in user['type']:
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
        for key in list(settings.keys()):
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
