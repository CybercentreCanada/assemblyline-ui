
from assemblyline.remote.datatypes.queues.comms import CommsQueue
from assemblyline_ui.sio.base import LOGGER, SecureNamespace, authenticated_only
from flask_socketio import emit, join_room


class FileCommentNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.background_task = None
        self.stop = False
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, sid):
        if len(self.connections) == 0:
            with self.connections_lock:
                self.stop = True

    def comments_change(self, user_info):
        q = CommsQueue('file_comments', private=True)
        try:
            for msg in q.listen():
                if self.stop:
                    break
                sha256 = dict(msg).get('sha256', None)
                if sha256 is not None:
                    self.socketio.emit('refresh_comments', None, room=sha256, namespace=self.namespace)
        except Exception:
            LOGGER.exception(f"SocketIO:{self.namespace} - {user_info['display']}")
        finally:
            LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Connection to client was terminated")

    @authenticated_only
    def on_enter_room(self, data, user_info):

        sha256 = dict(data).get('sha256', None)
        if sha256 is None:
            return

        LOGGER.info(
            f"SocketIO:{self.namespace} - {user_info['display']} - "
            f"User has started monitoring comments on file {sha256}")

        join_room(sha256)

        with self.connections_lock:
            self.stop = False
            if self.background_task is None:
                self.background_task = self.socketio.start_background_task(
                    target=self.comments_change, user_info=user_info)

    @ authenticated_only
    def on_comments_change(self, data, user_info):
        q = CommsQueue('file_comments', private=True)
        sha256 = dict(data).get('sha256', None)
        if sha256 is not None:
            q.publish({'sha256': sha256})
