
from flask_socketio import emit, join_room, leave_room

from assemblyline_ui.sio.base import LOGGER, SecureNamespace, authenticated_only


class FileCommentNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.background_task = None
        self.stop = False
        super().__init__(namespace=namespace)

    @authenticated_only
    def on_enter_room(self, data, user_info):
        join_room(f"file_comments_{data['sha256']}")
        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} joined the room: {data['sha256']}")
        # self.enter_room(data['sha256'])

    @authenticated_only
    def on_leave_room(self, data, user_info):
        leave_room(f"file_comments_{data['sha256']}")
        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} left the room: {data['sha256']}")

    @authenticated_only
    def on_comments_change(self, data, user_info):
        emit('refresh_comments', None, namespace=self.namespace,
             room=f"file_comments_{data['sha256']}", include_self=False)
        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} made a new comment in room: {data['sha256']}")
