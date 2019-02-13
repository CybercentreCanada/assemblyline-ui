
from flask import abort, request, session as flsk_session

from al_ui.config import AUDIT, AUDIT_LOG, AUDIT_KW_TARGET, KV_SESSION
from al_ui.http_exceptions import AccessDeniedException
from al_ui.config import config
from assemblyline.common.isotime import now


class BaseSecurityRenderer(object):
    def __init__(self, require_admin=False, audit=True, required_priv=None, allow_readonly=True):
        if required_priv is None:
            required_priv = ["E"]

        self.require_admin = require_admin
        self.audit = audit and AUDIT
        self.required_priv = required_priv
        self.allow_readonly = allow_readonly

    def audit_if_required(self, args, kwargs, logged_in_uname, user, func):
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
                AUDIT_LOG.info("%s [%s] :: %s(%s)" % (logged_in_uname,
                                                      user['classification'],
                                                      func.__name__,
                                                      ", ".join(params_list)))

    def extra_session_checks(self, session):
        pass

    def get_logged_in_user(self):
        session_id = flsk_session.get("session_id", None)

        if not session_id:
            abort(401)

        session = KV_SESSION.get(session_id)

        if not session:
            abort(401)
        else:
            cur_time = now()
            if session.get('expire_at', 0) < cur_time:
                KV_SESSION.pop(session_id)
                abort(401)
            else:
                session['expire_at'] = cur_time + session.get('duration', 3600)

        if request.headers.get("X-Forward-For", None) != session.get('ip', None) or \
                request.headers.get("User-Agent", None) != session.get('user_agent', None):
            abort(401)

        KV_SESSION.set(session_id, session)

        self.extra_session_checks(session)

        return session.get("username", None)

    def test_require_admin(self, user, r_type):
        if self.require_admin and not user['is_admin']:
            raise AccessDeniedException(f"{r_type} {request.path} requires ADMIN privileges")

    def test_readonly(self, r_type):
        if not self.allow_readonly and config.ui.read_only:
            raise AccessDeniedException(f"{r_type} not allowed in read-only mode")
