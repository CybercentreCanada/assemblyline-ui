from flask import abort, request, current_app, session as flsk_session

from assemblyline.common.isotime import now
from assemblyline.remote.datatypes.queues.named import NamedQueue
from assemblyline_ui.config import AUDIT, AUDIT_LOG, AUDIT_KW_TARGET, KV_SESSION
from assemblyline_ui.config import config
from assemblyline_ui.http_exceptions import AuthenticationException
from assemblyline_ui.security.apikey_auth import validate_apikey
from assemblyline_ui.security.ldap_auth import validate_ldapuser
from assemblyline_ui.security.oauth_auth import validate_oauth
from assemblyline_ui.security.second_factor_auth import validate_2fa
from assemblyline_ui.security.userpass_auth import validate_userpass

nonpersistent_config = {
    'host': config.core.redis.nonpersistent.host,
    'port': config.core.redis.nonpersistent.port,
    'ttl': config.auth.internal.failure_ttl
}


class BaseSecurityRenderer(object):
    def __init__(self, require_type=None, audit=True, required_priv=None, allow_readonly=True):
        if required_priv is None:
            required_priv = ["E"]
        if require_type is None:
            require_type = ["user"]

        self.require_type = require_type
        self.audit = audit and AUDIT
        self.required_priv = required_priv
        self.allow_readonly = allow_readonly

    def audit_if_required(self, args, kwargs, logged_in_uname, user, func, impersonator=None):
        if self.audit:
            # noinspection PyBroadException
            try:
                json_blob = request.json
                if not isinstance(json_blob, dict):
                    json_blob = {}
            except Exception:
                json_blob = {}

            params_list = list(args) + \
                ["%s=%s" % (k, v) for k, v in kwargs.items() if k in AUDIT_KW_TARGET] + \
                ["%s=%s" % (k, v) for k, v in request.args.items() if k in AUDIT_KW_TARGET] + \
                ["%s=%s" % (k, v) for k, v in json_blob.items() if k in AUDIT_KW_TARGET]

            if len(params_list) != 0:
                if impersonator:
                    audit_user = f"{impersonator} on behalf of {logged_in_uname}"
                else:
                    audit_user = logged_in_uname
                AUDIT_LOG.info("%s [%s] :: %s(%s)" % (audit_user,
                                                      user['classification'],
                                                      func.__name__,
                                                      ", ".join(params_list)))

    def auto_auth_check(self):
        return None

    def extra_session_checks(self, session):
        pass

    def get_logged_in_user(self):
        auto_auth_uname = self.auto_auth_check()
        if auto_auth_uname is not None:
            return auto_auth_uname

        session_id = flsk_session.get("session_id", None)

        if not session_id:
            current_app.logger.debug('session_id cookie not found')
            abort(401)

        session = KV_SESSION.get(session_id)

        if not session:
            current_app.logger.debug(f'[{session_id}] session_id not found in redis')
            abort(401)
        else:
            cur_time = now()
            if session.get('expire_at', 0) < cur_time:
                KV_SESSION.pop(session_id)
                current_app.logger.debug(f'[{session_id}] session has expired '
                                         f'{session.get("expire_at", 0)} < {cur_time}')
                abort(401)
            else:
                session['expire_at'] = cur_time + session.get('duration', 3600)

        if config.ui.validate_session_ip and \
                request.headers.get("X-Forwarded-For", request.remote_addr) != session.get('ip', None):
            current_app.logger.debug(f'[{session_id}] X-Forwarded-For does not match session IP '
                                     f'{request.headers.get("X-Forwarded-For", None)} != {session.get("ip", None)}')
            abort(401)

        if config.ui.validate_session_useragent and \
                request.headers.get("User-Agent", None) != session.get('user_agent', None):
            current_app.logger.debug(f'[{session_id}] User-Agent does not match session user_agent '
                                     f'{request.headers.get("User-Agent", None)} != {session.get("user_agent", None)}')
            abort(401)

        KV_SESSION.set(session_id, session)

        self.extra_session_checks(session)

        return session.get("username", None)

    def test_require_type(self, user, r_type):
        for required_type in self.require_type:
            if required_type in user['type']:
                return

        abort(403, f"{r_type} {request.path} requires one of the following privileges: {', '.join(self.require_type)}")

    def test_readonly(self, r_type):
        if not self.allow_readonly and config.ui.read_only:
            abort(403, f"{r_type} not allowed in read-only mode")


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
    otp = auth.get('otp', 0)
    webauthn_auth_resp = auth.get('webauthn_auth_resp', None)
    state = ses.pop('state', None)
    password = auth.get('password', None)
    uname = auth.get('username', None)
    oauth_token = auth.get('oauth_token', None)

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
        validated_user, priv = validate_apikey(uname, apikey, storage)
        if validated_user:
            return validated_user, priv

        validated_user, priv = validate_oauth(uname, oauth_token)
        if not validated_user:
            validated_user, priv = validate_ldapuser(uname, password, storage)
        if not validated_user:
            validated_user, priv = validate_userpass(uname, password, storage)

        if validated_user:
            validate_2fa(validated_user, otp, state, webauthn_auth_resp, storage)
            return validated_user, priv

    except AuthenticationException:
        # Failure appended, push failure parameters
        auth_fail_queue.push({
            'remote_addr': req.remote_addr,
            'host': req.host,
            'full_path': req.full_path
        })

        raise

    raise AuthenticationException("None of the authentication methods succeeded")
