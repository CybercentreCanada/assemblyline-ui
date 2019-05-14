
import logging

from flask_socketio import emit

from al_ui.sio.base import LOGGER, SecureNamespace, authenticated_only
from assemblyline.common import forge
from assemblyline.remote.datatypes.queues.comms import CommsQueue


config = forge.get_config()
classification = forge.get_classification()

AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')


class SystemStatusNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.background_task_started = False
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, sid):
        if len(self.connections) == 0:
            with self.connections_lock:
                self.background_task_started = False

    # noinspection PyBroadException
    def monitor_system_status(self):
        with self.connections_lock:
            if self.background_task_started:
                return
            self.background_task_started = True

        q = CommsQueue('status', private=True)
        try:
            for msg in q.listen():
                if not self.background_task_started:
                    break

                message = msg['msg']
                msg_type = msg['msg_type']
                self.socketio.emit(msg_type, message, namespace=self.namespace)
                LOGGER.info(f"SocketIO:{self.namespace} - Sending {msg_type} event to all connected users.")

        except Exception:
            LOGGER.exception(f"SocketIO:{self.namespace}")
        finally:
            LOGGER.info(f"SocketIO:{self.namespace} - No more users connected to status monitoring, exiting thread...")

    @authenticated_only
    def on_monitor(self, data, user_info):
        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - User as started monitoring system status...")

        self.socketio.start_background_task(target=self.monitor_system_status)
        emit('monitoring', data)
