import json
import logging
import threading

from flask import Flask, request, session
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect

from assemblyline.common import forge, log as al_log
from assemblyline.remote.datatypes.hash import Hash
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline.remote.datatypes.queues.named import NamedQueue

config = forge.get_config()
datastore = forge.get_datastore()
classification = forge.get_classification()

app = Flask(__name__)
app.config['SECRET_KEY'] = config.ui.secret_key
socketio = SocketIO(app)

al_log.init_logging("ui")
AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')
LOGGER = logging.getLogger('assemblyline.ui.socketio')

KV_SESSION = Hash("flask_sessions",
                  host=config.core.redis.nonpersistent.host,
                  port=config.core.redis.nonpersistent.port,
                  db=config.core.redis.nonpersistent.db)

connections_lock = threading.RLock()
connections = {}
rooms = {}


def get_user_info(resquest_p, session_p):
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
            user_classification = user.get('classification', None)

    return {
        'uname': uname,
        'classification': user_classification,
        'ip': resquest_p.headers.get("X-Forward-For", None)
    }


# # noinspection PyBroadException
# @socketio.on('alert')
# def alert_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Alert - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     if AUDIT:
#         AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
#                                                  info.get('classification', classification.UNRESTRICTED),
#                                                  "socketsrv_alert_on"))
#     emit('connected', data)
#
#     q = CommsQueue('alerts', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 data = json.loads(msg['data'])
#                 if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
#                                                 data.get('body', {}).get('classification',
#                                                                          classification.UNRESTRICTED)):
#                     emit('AlertCreated', data)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Alert" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Alert - Connection to client was terminated" %
#                     (info.get('uname', None), info['ip']))
#         if AUDIT:
#             AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
#                                                     info.get('classification', classification.UNRESTRICTED),
#                                                     "socketsrv_alert_on"))
#
#
# # noinspection PyBroadException
# @socketio.on('monitor')
# def monitoring_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Monitor - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     emit('connected', data)
#
#     q = CommsQueue('status', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 data = json.loads(msg['data'])
#                 emit(data['mtype'], data)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Monitor" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Monitor - Connection to client was terminated" % (info.get('uname', None),
#                                                                                         info['ip']))
#
#
# def listen_callback(info, queue):
#     pass
#
#
# # noinspection PyBroadException
# @socketio.on('listen')
# def listen_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Listen - Event received => %s" % (info.get('uname', None), info['ip'], data))
#
#     try:
#         queue = NamedQueue(data['wq_id'], private=True)
#         if data['from_start']:
#             msg = queue.pop(timeout=15)
#
#             if msg is None:
#                 emit('error', {'err_msg': 'Never got any response from the dispatcher. Try reloading the page...',
#                                'status_code': 404, 'msg': None})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Timeout reached. Event terminated." % (info.get('uname', None),
#                                                                                               info['ip']))
#                 return
#             elif msg['status'] == 'START':
#                 emit('start', {'err_msg': None, 'status_code': 200, 'msg': "Start listening..."})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Emit start message" % (info.get('uname', None), info['ip']))
#
#             elif msg['status'] == 'STOP':
#                 emit('stop', {'err_msg': None, 'status_code': 200, 'msg': "All messages received, closing queue..."})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Event terminated gracefully." % (info.get('uname', None),
#                                                                                         info['ip']))
#                 return
#             else:
#                 emit('error', {'err_msg': 'Unexpected status code for the first message',
#                                'status_code': 500, 'msg': msg})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Unexpected message received. "
#                             "Event terminated." % (info.get('uname', None), info['ip']))
#                 return
#
#         while True:
#             msg = queue.pop(timeout=300)
#
#             if msg is None:
#                 emit('error', {'err_msg': 'Never got any response from the dispatcher. Try reloading the page...',
#                                'status_code': 404, 'msg': None})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Timeout reached. Event terminated." % (info.get('uname', None),
#                                                                                               info['ip']))
#                 break
#             if msg['status'] == 'STOP':
#                 emit('stop', {'err_msg': None, 'status_code': 200, 'msg': "All messages received, closing queue..."})
#                 LOGGER.info("[%s@%s] SocketIO:Listen - Event terminated gracefully." % (info.get('uname', None),
#                                                                                         info['ip']))
#                 break
#             elif msg['status'] == 'OK':
#                 emit('cachekey', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']})
#             elif msg['status'] == 'FAIL':
#                 emit('cachekeyerr', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']})
#
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Listen" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Listen - Connection to client was terminated" % (info.get('uname', None),
#                                                                                        info['ip']))
#
#
# # noinspection PyBroadException
# @socketio.on('submission')
# def submission_on(data):
#     info = get_user_info(request, session)
#
#     if info.get('uname', None) is None:
#         return
#
#     LOGGER.info("[%s@%s] SocketIO:Submission - Event received => %s" % (info.get('uname', None), info['ip'], data))
#     if AUDIT:
#         AUDIT_LOG.info("%s [%s] :: %s(start)" % (info.get('uname', None),
#                                                  info.get('classification', classification.UNRESTRICTED),
#                                                  "socketsrv_submission_on"))
#     emit('connected', data)
#
#     q = CommsQueue('traffic', private=True)
#     try:
#         for msg in q.listen():
#             if msg['type'] == "message":
#                 body = json.loads(msg['data'])
#                 submission_classification = body.get('body', {}).get('classification', classification.UNRESTRICTED)
#                 message = {
#                     'body': body,
#                     'mtype': 'SubmissionIngested',
#                     'reply_to': None,
#                     'sender': u'middleman',
#                     'succeeded': True,
#                     'to': u'*'
#                 }
#
#                 if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
#                                                 submission_classification):
#                     emit('SubmissionIngested', message)
#     except Exception:
#         LOGGER.exception("[%s@%s] SocketIO:Submission" % (info.get('uname', None), info['ip']))
#     finally:
#         LOGGER.info("[%s@%s] SocketIO:Submission - Connection to client was terminated" %
#                     (info.get('uname', None), info['ip']))
#         if AUDIT:
#             AUDIT_LOG.info("%s [%s] :: %s(stop)" % (info.get('uname', None),
#                                                     info.get('classification', classification.UNRESTRICTED),
#                                                     "socketsrv_submission_on"))

@socketio.on('connect')
def connection_received():
    info = get_user_info(request, session)

    if info.get('uname', None) is None:
        disconnect()

    LOGGER.info(f"SocketIO:Connect - New socketIO connection to user '{info['uname']}@{info['ip']}' established.")
    with connections_lock:
        connections[request.sid] = info


@socketio.on('disconnect')
def disconnect_received():
    with connections_lock:
        connections.pop(request.sid, None)
        for room_id in list(rooms.keys()):
            if rooms[room_id] == request.sid:
                rooms.pop(room_id, None)


def watch_room(queue_id):
    queue = NamedQueue(queue_id, private=True)
    while queue_id in rooms:
        msg = queue.pop(timeout=1)
        if msg is None:
            continue

        elif msg['status'] == 'START':
            socketio.emit('start', {'err_msg': None, 'status_code': 200, 'msg': "Start listening..."}, room=queue_id)
            LOGGER.info(f"SocketIO:Listen - Ignoring start message for room {queue_id} "
                        f"=> {connections[rooms[queue_id]]['uname']}")

        elif msg['status'] == 'STOP':
            socketio.emit('stop', {'err_msg': None, 'status_code': 200,
                          'msg': "All messages received, closing queue..."}, room=queue_id)
            LOGGER.info(f"SocketIO:Listen - Terminating messaging for room {queue_id} "
                        f"=> {connections[rooms[queue_id]]['uname']}")
            break
        elif msg['status'] == 'OK':
            socketio.emit('cachekey', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}, room=queue_id)
        elif msg['status'] == 'FAIL':
            socketio.emit('cachekeyerr', {'err_msg': None, 'status_code': 200, 'msg': msg['cache_key']}, room=queue_id)
        else:
            LOGGER.info(f"SocketIO:Listen - Unexpected message received for room {queue_id}: {msg}")

    with connections_lock:
        rooms.pop(queue_id, None)
    LOGGER.info(f"SocketIO:Listen - Room {queue_id} terminated.")

def create_room(queue_id, sid):
    with connections_lock:
        rooms[queue_id] = sid
    socketio.start_background_task(target=watch_room, queue_id=queue_id)

@socketio.on('listen')
def listen_on(data):
    info = connections[request.sid]
    queue_id = data['wq_id']
    LOGGER.info(f"SocketIO:Listen - Event received {data} => {info['uname']}")
    create_room(queue_id, request.sid)
    join_room(queue_id)
    #emit('start', {'err_msg': None, 'status_code': 200, 'msg': "Start listening..."})


if __name__ == '__main__':
    print(app.url_map)
    socketio.run(app, host="0.0.0.0", port=5002)
