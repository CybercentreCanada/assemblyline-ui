
from flask_socketio import join_room

from assemblyline_ui.sio.base import SecureNamespace, LOGGER, authenticated_only
from assemblyline.remote.datatypes.queues.named import NamedQueue


class LiveSubmissionNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.watch_queues = {}
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, sid):
        for watch_queue in list(self.watch_queues.keys()):
            if self.watch_queues[watch_queue] == sid:
                self.watch_queues.pop(watch_queue, None)

    def watch_message_queue(self, queue_id, user_info):
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
                    LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                                f"Max retry reach for queue: {queue_id}")
                    break
                continue

            retry = 0
            try:
                status = msg['status']
                key = msg.get('cache_key', None)
            except (KeyError, ValueError, TypeError):
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Unexpected message received for "
                            f"queue {queue_id}: {msg}")
                continue

            if status == 'START':
                self.socketio.emit('start', {'status_code': 200, 'msg': "Start listening..."},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                            f"Stating processing message on queue: {queue_id}")
                max_retry = 300

            elif status == 'STOP':
                self.socketio.emit('stop', {'status_code': 200,
                                            'msg': "All messages received, closing queue..."},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                            f"Stopping monitoring queue: {queue_id}")
                break
            elif status == 'OK':
                self.socketio.emit('cachekey', {'status_code': 200, 'msg': key},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Sending result key: {key}")
            elif status == 'FAIL':
                self.socketio.emit('cachekeyerr', {'status_code': 200, 'msg': key},
                                   room=queue_id, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Sending error key: {key}")
            else:
                LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Unexpected message received for "
                            f"queue {queue_id}: {msg}")

        with self.connections_lock:
            self.watch_queues.pop(queue_id, None)

        self.socketio.close_room(queue_id)

        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                    f"Watch queue thread terminated for queue: {queue_id}")

    @authenticated_only
    def on_listen(self, data, user_info):
        queue_id = data['wq_id']

        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                    f"Listening event received for queue: {queue_id}")

        with self.connections_lock:
            self.watch_queues[queue_id] = user_info['sid']
        self.socketio.start_background_task(target=self.watch_message_queue, queue_id=queue_id, user_info=user_info)

        join_room(queue_id)
