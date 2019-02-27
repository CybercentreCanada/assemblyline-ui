from assemblyline.common import forge
from assemblyline.remote.datatypes.hash import Hash

config = forge.get_config()
datastore = forge.get_datastore()

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port,
                  db=config.core.redis.nonpersistent.db)


def get_user_info(request_p, session_p):
    uname = None
    current_session = KV_SESSION.get(session_p.get("session_id", None))
    if current_session:
        if request_p.headers.get("X-Forward-For", None) == current_session.get('ip', None) and \
                request_p.headers.get("User-Agent", None) == current_session.get('user_agent', None):
            uname = current_session['username']

    user_classification = None
    if uname:
        user = datastore.user.get(uname, as_obj=False)
        if user:
            user_classification = user.get('classification', None)

    return {
        'uname': uname,
        'classification': user_classification,
        'ip': request_p.headers.get("X-Forward-For", None)
    }
