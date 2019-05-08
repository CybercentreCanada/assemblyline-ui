
from u2flib_server.u2f import complete_authentication

from assemblyline.common import forge
from assemblyline.common.codec import encode_file
from assemblyline.common.security import verify_password, get_totp_token
from assemblyline.remote.datatypes.queues.named import NamedQueue
from al_ui.config import config, APP_ID
from al_ui.http_exceptions import AuthenticationException

APP_NAME = "Assemblyline"
TEMPLATE_PREFIX = {}

basic_dn_parser = None

nonpersistent_config = {
    'host': config.core.redis.nonpersistent.host,
    'port': config.core.redis.nonpersistent.port,
    'db': config.core.redis.nonpersistent.db,
    'ttl': config.auth.internal.failure_ttl
}


##################
# Default site Create menu function
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
            {"class": "",
             "active": path.startswith("/yara_standard.html"),
             "link": "/yara_standard.html",
             "title": "Yara Malware Standard"},
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
             "active": path.startswith("/alerts.html"),
             "link": "/alerts.html",
             "title": "Alerts",
             "has_submenu": False}]

    if not config.ui.read_only:
        signature_submenu = [
            {"class": "dropdown-header",
             "active": False,
             "link": None,
             "title": "Static Analysis"},
            {"class": "",
             "active": path.startswith("/tc_signatures.html"),
             "link": "/tc_signatures.html",
             "title": "Tagcheck signatures",
             "has_submenu": False},
            {"class": "",
             "active": path.startswith("/signatures.html"),
             "link": "/signatures.html",
             "title": "Yara signatures",
             "has_submenu": False}
        ]
        menu.extend([{"class": "",
                      "active": path.startswith("/signatures.html") or path.startswith("/tc_signatures.html"),
                      "link": "#",
                      "title": "Signatures",
                      "has_submenu": True,
                      "submenu": signature_submenu}])

    menu.extend([
        {"class": "hidden-md hidden-lg",
         "active": path.startswith("/search.html"),
         "link": "/search.html",
         "title": "Search",
         "has_submenu": False},
        {"class": "",
         "active": path.startswith("/api_doc.html") or
            path.startswith("/classification_help.html") or
            path.startswith("/configuration.html") or
            path.startswith("/heuristics.html") or
            path.startswith("/heuristics_stats.html") or
            path.startswith("/signature_statistics.html") or
            path.startswith("/search_help.html") or
            path.startswith("/services.html") or
            path.startswith("/yara_standard.html"),
         "link": "#",
         "title": "Help",
         "has_submenu": True,
         "submenu": help_submenu}])

    return menu


def register_site_specific_routes(_):
    pass


# noinspection PyUnusedLocal
def default_authenticator(auth, req, ses, storage):
    # This is assemblyline authentication procedure
    # It will try to authenticate the user in the following order until a method is successful
    #    apikey
    #    username/password
    #    PKI DN
    #
    # During the authentication procedure the user/pass and DN methods will be subject to OTP challenge
    # if OTP is allowed on the server and has been turned on by the user
    #
    # Apikey authentication procedure is not subject to OTP challenge but has limited functionality

    apikey = auth.get('apikey', None)
    dn = auth.get('dn', None)
    otp = auth.get('otp', 0)
    u2f_response = auth.get('u2f_response', None)
    u2f_challenge = ses.pop('_u2f_challenge_', None)
    password = auth.get('password', None)
    uname = auth.get('username', None) or dn

    if not uname:
        raise AuthenticationException('No user specified for authentication')

    # Bruteforce protection
    auth_fail_queue = NamedQueue("ui-failed-%s" % uname, **nonpersistent_config)
    if auth_fail_queue.length() >= config.auth.internal.max_failures:
        # Failed 'max_failures' times, stop trying... This will timeout in 'failure_ttl' seconds
        raise AuthenticationException("Maximum password retry of {retry} was reached. "
                                      "This account is locked for the next {ttl} "
                                      "seconds...".format(retry=config.auth.internal.max_failures,
                                                          ttl=config.auth.internal.failure_ttl))

    try:
        validated_user, priv = apikey_handler(uname, apikey, storage)
        if validated_user:
            return validated_user, priv

        validated_user, priv = userpass_handler(uname, password, storage)
        if validated_user:
            validate_2fa(validated_user, otp, u2f_challenge, u2f_response, storage)
            return validated_user, priv

        validated_user, priv = dn_handler(dn, storage)
        if validated_user:
            validate_2fa(validated_user, otp, u2f_challenge, u2f_response, storage)
            return validated_user, priv

    except AuthenticationException as ae:
        # Failure appended, push failure parameters
        auth_fail_queue.push({
            'remote_addr': req.remote_addr,
            'host': req.host,
            'full_path': req.full_path
        })

        raise

    raise AuthenticationException("None of the authentication methods succeeded")


def validate_apikey(username, apikey, storage):
    # This function identifies the user via the internal API key functionality
    #   NOTE: It is not recommended to overload this function but you can still do it
    if config.auth.allow_apikeys and apikey:
        user_data = storage.user.get(username)
        if user_data:
            name, apikey_password = apikey.split(":", 1)
            key = user_data.apikeys.get(name, None)
            if key is not None:
                if verify_password(apikey_password, key.password):
                    return username, key.acl

        raise AuthenticationException("Invalid apikey")

    return None, None


# noinspection PyUnusedLocal
def validate_dn(dn, storage):
    # There are no default way to handle DN, You need to overload this function if you
    # want DN support to work properly
    return None, None


def validate_userpass(username, password, storage):
    # This function uses the internal authenticator to identify the user
    # You can overload this to pass username/password to an LDAP server for exemple
    if config.auth.internal.enabled and username and password:
        user = storage.user.get(username)
        if user:
            if verify_password(password, user.password):
                return username, ["R", "W", "E"]

        raise AuthenticationException("Wrong username or password")

    return None, None


# noinspection PyBroadException
def validate_2fa(username, otp_token, u2f_challenge, u2f_response, storage):
    u2f_enabled = False
    otp_enabled = False
    u2f_error = False
    otp_error = False
    report_errors = False

    # Get user
    user_data = storage.user.get(username)

    # Test u2f
    if config.auth.allow_u2f:
        u2f_devices = user_data.u2f_devices
        if isinstance(u2f_devices, list):
            u2f_devices = {"default": d for d in u2f_devices}

        registered_keys = u2f_devices.values()
        if registered_keys:
            # U2F is enabled for user
            u2f_enabled = True
            report_errors = True
            if u2f_challenge and u2f_response:
                try:
                    complete_authentication(u2f_challenge, u2f_response, [APP_ID])
                    return
                except Exception:
                    u2f_error = True

    # Test OTP
    if config.auth.allow_2fa:
        otp_sk = user_data.otp_sk
        if otp_sk:
            # OTP is enabled for user
            otp_enabled = True
            report_errors = True
            if otp_token:
                if get_totp_token(otp_sk) != otp_token:
                    otp_error = True
                else:
                    return

    if report_errors:
        if u2f_error:
            # Wrong response to challenge
            raise AuthenticationException("Wrong U2F Security Token")
        elif otp_error:
            # Wrong token provided
            raise AuthenticationException("Wrong OTP token")
        elif u2f_enabled:
            # No challenge/response provided and U2F is enabled
            raise AuthenticationException("Wrong U2F Security Token")
        elif otp_enabled:
            # No OTP Token provided and OTP is enabled
            raise AuthenticationException("Wrong OTP token")

        # This should never hit
        raise AuthenticationException("Unknown 2FA Authentication error")


apikey_handler = forge.get_site_specific_apikey_handler(config=config)
dn_handler = forge.get_site_specific_dn_handler(config=config)
userpass_handler = forge.get_site_specific_userpass_handler(config=config)

context = {
    'TEMPLATE_PREFIX': TEMPLATE_PREFIX,
    'APP_NAME': APP_NAME,
    'create_menu': create_menu,
    'encode_file': encode_file,
    'register_site_specific_routes': register_site_specific_routes,
}
