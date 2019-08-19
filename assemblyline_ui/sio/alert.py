
import logging

from flask_socketio import emit, join_room

from assemblyline_ui.sio.base import LOGGER, SecureNamespace, authenticated_only
from assemblyline.common import forge
from assemblyline.remote.datatypes.queues.comms import CommsQueue


config = forge.get_config()
classification = forge.get_classification()

AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')


class AlertMonitoringNamespace(SecureNamespace):
    # noinspection PyBroadException
    def monitor_alerts(self, user_info):
        sid = user_info['sid']
        q = CommsQueue('alerts', private=True)
        try:
            for msg in q.listen():
                if sid not in self.connections:
                    break

                alert = msg['msg']
                msg_type = msg['msg_type']
                if classification.is_accessible(user_info['classification'],
                                                alert.get('classification', classification.UNRESTRICTED)):
                    self.socketio.emit(msg_type, alert, room=sid, namespace=self.namespace)
                    LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - "
                                f"Sending {msg_type} event for alert matching ID: {alert['alert_id']}")

                    if AUDIT:
                        AUDIT_LOG.info(
                            f"{user_info['uname']} [{user_info['classification']}]"
                            f" :: AlertMonitoringNamespace.get_alert(alert_id={alert['alert_id']})")

        except Exception:
            LOGGER.exception(f"SocketIO:{self.namespace} - {user_info['display']}")
        finally:
            LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Connection to client was terminated")

    @authenticated_only
    def on_alert(self, data, user_info):
        LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - User as started monitoring alerts...")

        join_room(user_info['sid'])
        self.socketio.start_background_task(target=self.monitor_alerts, user_info=user_info)

        emit('monitoring', data, room=user_info['sid'], namespace=self.namespace)
