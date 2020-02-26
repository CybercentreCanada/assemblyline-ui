import base64
import hashlib
import ldap
import logging
import time

from assemblyline.common.str_utils import safe_str
from assemblyline_ui.config import config
from assemblyline_ui.http_exceptions import AuthenticationException

log = logging.getLogger('assemblyline.ldap_authenticator')


#####################################################
# Functions
#####################################################
class BasicLDAPWrapper(object):
    CACHE_SEC_LEN = 300

    def __init__(self, ldap_config):
        """

        :param ldap_config: dict containing configuration params for LDAP
        """
        self.ldap_uri = ldap_config.uri
        self.base = ldap_config.base
        self.uid_lookup = f"{ldap_config.uid_field}=%s"

        # TODO: - this isn't fully implemented
        self.classification_groups = ldap_config.classification_groups
        self.classification_mappings = ldap_config.classification_mappings

        self.cache = {}
        self.get_obj_cache = {}

    def create_connection(self):
        if "ldaps://" in self.ldap_uri:
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        ldap_server = ldap.initialize(self.ldap_uri)
        ldap_server.protocol_version = ldap.VERSION3
        ldap_server.set_option(ldap.OPT_REFERRALS, 0)
        return ldap_server

    def get_user_classification(self, uid, ldap_server=None):
        """
        Extend the users classification information with the configured group information

        NB: This is not fully implemented at this point

        :param uid:
        :param ldap_server:
        :return:
        """
        # TODO: - this isn't fully implemented

        ret = ""
        for gq in self.classification_groups:
            res = [x[0] for x in self.get_object(gq % uid, ldap_server)["ldap"]]
            for group_dn in res:
                if group_dn in self.classification_mappings:
                    ret += self.classification_mappings[group_dn]

        return ret

    def get_object(self, ldap_object, ldap_server=None):
        cur_time = int(time.time())
        cache_entry = self.get_obj_cache.get(ldap_object, None)
        if cache_entry and cache_entry['expiry'] > cur_time:
            # load obj from cache
            return {"error": None, "ldap": cache_entry['details'], "cached": True}

        if not ldap_server:
            try:
                ldap_server = self.create_connection()
            except Exception as le:
                return {"error": "Error connecting to ldap server. Reason: %s" % (repr(le)),
                        "ldap": None, "cached": False}

        try:
            res = ldap_server.search_s(self.base, ldap.SCOPE_SUBTREE, ldap_object)

            # Save cache get_obj
            self.get_obj_cache[ldap_object] = {"expiry": cur_time + self.CACHE_SEC_LEN, "details": res}

            return {"error": None, "ldap": res, "cached": False}
        except ldap.UNWILLING_TO_PERFORM:
            return {"error": "ldap server is unwilling to perform the operation.", "ldap": None, "cached": False}
        except ldap.LDAPError as le:
            return {"error": "An error occurred while talking to the ldap server: %s" % repr(le), "ldap": None,
                    "cached": False}

    # noinspection PyBroadException
    def login(self, user, password):
        cur_time = int(time.time())
        password_digest = hashlib.md5(password.encode('utf-8')).hexdigest()
        cache_entry = self.cache.get(user, None)
        if cache_entry:
            if cache_entry['expiry'] > cur_time and cache_entry['password'] == password_digest:
                cache_entry["cached"] = True
                return cache_entry

        try:
            ldap_server = self.create_connection()
            dn, details = self.get_details_from_uid(user, ldap_server=ldap_server)
            if dn:
                ldap_server.simple_bind_s(dn, password)
                cache_entry = {"password": password_digest, "expiry": cur_time + self.CACHE_SEC_LEN,
                               "connection": ldap_server, "details": details, "cached": False}
                self.cache[user] = cache_entry
                return cache_entry
        except Exception as e:
            # raise AuthenticationException('Unable to login to ldap server. [%s]' % str(e))
            log.exception('Unable to login to ldap server. [%s]' % str(e))
        return None

    # noinspection PyBroadException
    def get_details_from_uid(self, uid, ldap_server=None):
        res = self.get_object(self.uid_lookup % uid, ldap_server)
        if res['error']:
            log.error(res['error'])
            return None

        try:
            return res['ldap'][0]
        except Exception:
            return None


def get_attribute(ldap_login_info, key, safe=True):
    details = ldap_login_info.get('details')
    if details:
        value = details.get(key, [])
        if len(value) >= 1:
            if safe:
                return safe_str(value[0])
            else:
                return value[0]

    return None


def validate_ldapuser(username, password, storage):
    if config.auth.ldap.enabled and username and password:
        ldap_obj = BasicLDAPWrapper(config.auth.ldap)
        ldap_info = ldap_obj.login(username, password)
        if ldap_info:
            cur_user = storage.user.get(username, as_obj=False) or {}

            # Make sure the user exists in AL and is in sync
            if not cur_user or config.auth.ldap.auto_sync:
                # Generate user data from ldap
                data = dict(
                    uname=username,
                    name=get_attribute(ldap_info, config.auth.ldap.name_field) or username,
                    email=get_attribute(ldap_info, config.auth.ldap.email_field),
                    password="__LDAP__"
                )

                # Save the user avatar avatar from ldap
                img_data = get_attribute(ldap_info, config.auth.ldap.image_field, safe=False)
                if img_data:
                    b64_img = base64.b64encode(img_data).decode()
                    avatar = f'data:image/{config.auth.ldap.image_format};base64,{b64_img}'
                    storage.user_avatar.save(username, avatar)

                # Save the updated user
                cur_user.update(data)
                storage.user.save(username, cur_user)

            return username.lower(), ["R", "W", "E"]
        elif config.auth.internal.enabled:
            # Fallback to internal auth
            pass
        else:
            raise AuthenticationException("Wrong LDAP username or password")

    return None, None
