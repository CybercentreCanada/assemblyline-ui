try:
    from gevent.monkey import patch_all
    patch_all()
except ImportError:
    patch_all = None

import json
import logging

from flask import Flask, request, session
from flask_socketio import SocketIO, emit

from assemblyline.common import forge, log as al_log
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
datastore = forge.get_datastore()
classification = forge.get_classification()

app = Flask(__name__)
app.config['SECRET_KEY'] = config.ui.secret_key
socketio = SocketIO(app, async_mode='gevent')

al_log.init_logging("ui")
AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui.socketio')

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port,
                  db=config.core.redis.nonpersistent.db)


class AuthenticationException(Exception):
    pass


def login(resquest_p, session_p):
    src_ip = resquest_p.headers.get("X-Forward-For", resquest_p.remote_addr)
    uname = None
    current_session = KV_SESSION.get(session_p.get("session_id", None))
    if current_session:
        if resquest_p.headers.get("X-Forward-For", None) == current_session.get('ip', None) and \
                resquest_p.headers.get("User-Agent", None) == current_session.get('user_agent', None):
            uname = current_session['username']

    user_classification = None
    if uname:
        user = datastore.user.get(uname, as_obj=False)
        if user:
            user_classification = user.get('classification', classification.UNRESTRICTED)

        return {
            'uname': uname,
            'classification': user_classification,
            'ip': src_ip
        }

    raise AuthenticationException(f"Un-authenticated connection attempt rejected from ip: {src_ip}")


# noinspection PyBroadException
@socketio.on('alert')
def alert_on(data):
    try:
        info = login(request, session)
    except AuthenticationException as e:
        LOGGER.warning(f"SocketIO:Alert - {str(e)}")
        return

    LOGGER.info(f"SocketIO:Alert - {info['uname']}@{info['ip']} - Event received => {data}")
    emit('connected', data, ignore_queue=True)

    q = CommsQueue('alerts', private=True)
    try:
        for msg in q.listen():
            alert = msg['msg']
            msg_type = msg['msg_type']
            if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
                                            alert.get('classification', classification.UNRESTRICTED)):
                emit(msg_type, alert, ignore_queue=True)
                LOGGER.info(f"SocketIO:Alert - {info['uname']}@{info['ip']} - "
                            f"Sending {msg_type} event for alert matching ID: {alert['alert_id']}")
                if AUDIT:
                    AUDIT_LOG.info(
                        f"{info['uname']} [{info['classification']}] "
                        f":: socketio_server.alert_on.send(alert_id={alert['alert_id']})")

    except Exception:
        LOGGER.exception(f"SocketIO:Alert - {info['uname']}@{info['ip']}")
    finally:
        LOGGER.info(f"SocketIO:Alert - {info['uname']}@{info['ip']} - Connection to client was terminated")


# noinspection PyBroadException
@socketio.on('monitor')
def monitoring_on(data):
    try:
        info = login(request, session)
    except AuthenticationException as e:
        LOGGER.warning(f"SocketIO:Alert - {str(e)}")
        return

    LOGGER.info("[%s@%s] SocketIO:Monitor - Event received => %s" % (info.get('uname', None), info['ip'], data))
    emit('connected', data)

    q = CommsQueue('status', private=True)
    try:
        for msg in q.listen():
            if msg['type'] == "message":
                data = json.loads(msg['data'])
                emit(data['mtype'], data)
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Monitor" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Monitor - Connection to client was terminated" % (info.get('uname', None),
                                                                                        info['ip']))


# noinspection PyBroadException
@socketio.on('listen')
def listen_on(data):
    try:
        info = login(request, session)
    except AuthenticationException as e:
        LOGGER.warning(f"SocketIO:Alert - {str(e)}")
        return

    queue_id = data['wq_id']
    LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Listening event received for queue: {queue_id}")
    try:
        u = NamedQueue(queue_id, private=True)
        max_retry = 5
        retry = 0
        while True:
            msg = u.pop(timeout=1)
            retry += 1
            if msg is None:
                if retry >= max_retry:
                    emit('error', {'status_code': 503, 'msg': "Dispatcher does not seem to be responding..."})
                    LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Max retry reach for queue: {queue_id}")
                    break
                emit('cachekey', {'status_code': 200, 'msg': "292457b9950aef4a48a1284356f577f562c945ea9f7d964e802afe58a9141f7c.Metadefender.v4_0_0_2e1fa7e.c0"})
                continue



            try:
                status = msg['status']
                key = msg.get('cache_key', None)
            except (KeyError, ValueError, TypeError):
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Unexpected message received for "
                            f"queue {queue_id}: {msg}")
                continue

            if status == 'START':
                emit('start', {'status_code': 200, 'msg': "Start listening..."})
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - "
                            f"Stating processing message on queue: {queue_id}")
                max_retry = 5
                retry = 0
            elif status == 'STOP':
                emit('stop', {'status_code': 200, 'msg': "All messages received, closing queue..."})
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Stopping monitoring queue: {queue_id}")
                break
            elif status == 'OK':
                emit('cachekey', {'status_code': 200, 'msg': key})
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Sending result key: {key}")
                retry = 0
            elif status == 'FAIL':
                emit('cachekeyerr', {'status_code': 200, 'msg': key})
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Sending error key: {key}")
                retry = 0
            else:
                LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Unexpected message received. "
                            "Event terminated.")

    except Exception:
        LOGGER.exception(f"SocketIO:Listen - {info['uname']}@{info['ip']}")
    finally:
        LOGGER.info(f"SocketIO:Listen - {info['uname']}@{info['ip']} - Connection to client was terminated")


# noinspection PyBroadException
@socketio.on('submission')
def submission_on(data):
    try:
        info = login(request, session)
    except AuthenticationException as e:
        LOGGER.warning(f"SocketIO:Alert - {str(e)}")
        return

    LOGGER.info("[%s@%s] SocketIO:Submission - Event received => %s" % (info.get('uname', None), info['ip'], data))
    if AUDIT:
        AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
                                                 info.get('classification', classification.UNRESTRICTED),
                                                 "socketsrv_submission_on"))
    emit('connected', data)

    q = CommsQueue('traffic', private=True)
    try:
        for msg in q.listen():
            if msg['type'] == "message":
                body = json.loads(msg['data'])
                submission_classification = body.get('body', {}).get('classification', classification.UNRESTRICTED)
                message = {
                    'body': body,
                    'mtype': 'SubmissionIngested',
                    'reply_to': None,
                    'sender': u'middleman',
                    'succeeded': True,
                    'to': u'*'
                }

                if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
                                                submission_classification):
                    emit('SubmissionIngested', message)
    except Exception:
        LOGGER.exception("[%s@%s] SocketIO:Submission" % (info.get('uname', None), info['ip']))
    finally:
        LOGGER.info("[%s@%s] SocketIO:Submission - Connection to client was terminated" %
                    (info.get('uname', None), info['ip']))
        if AUDIT:
            AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
                                                    info.get('classification', classification.UNRESTRICTED),
                                                    "socketsrv_submission_on"))


if __name__ == '__main__':
    LOGGER.info("SocketIO server ready to receive connections...")
    socketio.run(app, host="0.0.0.0", port=5002)
