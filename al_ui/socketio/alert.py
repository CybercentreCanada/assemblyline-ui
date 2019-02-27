
import logging

from flask import request
from flask_socketio import emit

from al_ui.socketio.base import get_request_id, Namespace, LOGGER, SecureNamespace, authenticated_only
from assemblyline.common import forge
from assemblyline.remote.datatypes.queues.comms import CommsQueue


config = forge.get_config()
classification = forge.get_classification()

AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')


class AlertMonitoringNamespace(SecureNamespace):
    def __init__(self, namespace=None):
        self.background_task_started = False
        super().__init__(namespace=namespace)

    def _extra_cleanup(self, _):
        if len(self.connections.keys()) == 0:
            self.background_task_started = False

    # noinspection PyBroadException
    def monitor_alerts(self, sid, info):
        if not self.background_task_started:
            self.background_task_started = True
        else:
            return

        q = CommsQueue('alerts', private=True)
        try:
            for msg in q.listen():
                alert = msg['msg']
                msg_type = msg['msg_type']
                if classification.is_accessible(info.get('classification', classification.UNRESTRICTED),
                                                alert.get('classification', classification.UNRESTRICTED)):
                    self.socketio.emit(msg_type, alert, namespace=self.namespace)
                    LOGGER.info(f"SocketIO:{self.namespace} - {self.get_user_from_sid(sid)} - "
                                f"Sending {msg_type} event for alert matching ID: {alert['alert_id']}")
                    if AUDIT:
                        AUDIT_LOG.info(
                            f"{info.get('uname', None)} [{info.get('classification', classification.UNRESTRICTED)}]"
                            f" :: AlertMonitoringNamespace.get_alert({alert['alert_id']})")
        except Exception:
            LOGGER.exception(f"SocketIO:{self.namespace} - {self.get_user_from_sid(sid)}")
        finally:
            LOGGER.info(f"SocketIO:{self.namespace} - {self.get_user_from_sid(sid)} - "
                        f"Connection to client was terminated")
            if AUDIT:
                AUDIT_LOG.info(f"{info.get('uname', None)} [{info.get('classification', classification.UNRESTRICTED)}]"
                               f" :: AlertMonitoringNamespace.on_alert(stop)")

    @authenticated_only
    def on_alert(self, data):
        sid = get_request_id(request)
        info = self.get_info_from_sid(sid)

        LOGGER.info(f"SocketIO:{self.namespace} - {self.get_user_from_sid(sid)} - "
                    f"User as started monitoring alerts...")
        if AUDIT:
            AUDIT_LOG.info(f"{info.get('uname', None)} [{info.get('classification', classification.UNRESTRICTED)}]"
                           f" :: AlertMonitoringNamespace.on_alert(start)")

        self.socketio.start_background_task(target=self.monitor_alerts, sid=sid, info=info)
        emit('connected', data, namespace=self.namespace)
