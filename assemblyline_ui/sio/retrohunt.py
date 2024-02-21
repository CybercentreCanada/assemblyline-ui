from flask_socketio import join_room

from assemblyline_ui.sio.base import LOGGER, datastore, classification, config, SecureNamespace, authenticated_only
from assemblyline_ui.helper.retrohunt import get_hauntedhouse_client


haunted_house_client = get_hauntedhouse_client(config)


class RetrohuntNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.watch_socket = {}
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, sid):
        for watch_queue in list(self.watch_socket.keys()):
            if self.watch_socket[watch_queue] == sid:
                self.watch_socket.pop(watch_queue, None)

    def watch_search_socket(self, search_key, user_info):
        if haunted_house_client:
            for message in haunted_house_client.search_status(search_key):
                if search_key not in self.watch_socket:
                    break
                
                self.socketio.emit('status', message, room=search_key, namespace=self.namespace)
                # LOGGER.info("SocketIO:%s - %s - Max retry reach for queue: %s",
                #             self.namespace, user_info['display'], queue_id)

        with self.connections_lock:
            self.watch_socket.pop(search_key, None)

        self.socketio.close_room(search_key)

        LOGGER.info("SocketIO:%s - %s - Watch thread terminated for search: %s",
                    self.namespace, user_info['display'], search_key)

    @authenticated_only
    def on_listen(self, data, user_info):
        search_key = data['key']

        doc = datastore.retrohunt.get(search_key, as_obj=False)
        if not doc or not classification.is_accessible(user_info['classification'], doc['classification']):
            return

        LOGGER.info("SocketIO:%s - %s - Listening event received for search: %s",
                    self.namespace, user_info['display'], search_key)

        with self.connections_lock:
            self.watch_socket[search_key] = user_info['sid']
        self.socketio.start_background_task(target=self.watch_search_socket, search_key=search_key, user_info=user_info)

        join_room(search_key)
