
from flask import request
from flask_socketio import join_room

from al_ui.socketio.base import get_request_id, SecureNamespace, LOGGER
from assemblyline.remote.datatypes.queues.named import NamedQueue


class LiveSubmissionNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.watch_queues = {}
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, sid):
        for watch_queue in list(self.watch_queues.keys()):
            if self.watch_queues[watch_queue] == sid:
                self.watch_queues.pop(watch_queue, None)

    def watch_message_queue(self, queue_id):
        uname = self.get_user_from_sid(self.watch_queues[queue_id])
        queue = NamedQueue(queue_id, private=True)
        max_retry = 30
        retry = 0
        while queue_id in self.watch_queues:
            msg = queue.pop(timeout=1)
            if msg is None:
                retry += 1
                if retry >= max_retry:
                    self.socketio.emit('error', {'status_code': 503,
                                                 'msg': "Dispatcher does not seem to be responding..."},
                                       room=queue_id, namespace=self.namespace)
                    LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Max retry reach for queue: {queue_id}")
                    break
                continue

            retry = 0
            try:
                status = msg['status']
                key = msg.get('cache_key', None)
            except (KeyError, ValueError, TypeError):
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Unexpected message received for "
                            f"queue {queue_id}: {msg}")
                continue

            if status == 'START':
                self.socketio.emit('start', {'status_code': 200, 'msg': "Start listening..."},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Stating processing message on queue: {queue_id}")
                max_retry = 300

            elif status == 'STOP':
                self.socketio.emit('stop', {'status_code': 200,
                                            'msg': "All messages received, closing queue..."},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - "
                            f"Stopping monitoring queue: {queue_id}")
                break
            elif status == 'OK':
                self.socketio.emit('cachekey', {'status_code': 200, 'msg': key},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Sending result key: {key}")
            elif status == 'FAIL':
                self.socketio.emit('cachekeyerr', {'status_code': 200, 'msg': key},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Sending error key: {key}")
            else:
                LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Unexpected message received for "
                            f"queue {queue_id}: {msg}")

        with self.connections_lock:
            self.watch_queues.pop(queue_id, None)

        self.socketio.close_room(queue_id)

        LOGGER.info(f"SocketIO:{self.namespace} - {uname} - Watch queue thread terminated for queue: {queue_id}")

    def on_listen(self, data):
        sid = get_request_id(request)
        queue_id = data['wq_id']

        LOGGER.info(f"SocketIO:{self.namespace} - {self.get_user_from_sid(sid)} - "
                    f"Listening event received for queue: {queue_id}")

        with self.connections_lock:
            self.watch_queues[queue_id] = sid
        self.socketio.start_background_task(target=self.watch_message_queue, queue_id=queue_id)

        join_room(queue_id)
