
import logging

from flask_socketio import emit, join_room

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.sio.base import LOGGER, SecureNamespace, authenticated_only
from assemblyline.common import forge
from assemblyline.remote.datatypes.queues.comms import CommsQueue


config = forge.get_config()
classification = forge.get_classification()

AUDIT = config.ui.audit
AUDIT_LOG = logging.getLogger('assemblyline.ui.audit')


class SubmissionMonitoringNamespace(SecureNamespace):
    # noinspection PyBroadException
    def monitor_submissions(self, user_info):
        sid = user_info['sid']
        q = CommsQueue('submissions', private=True)
        try:
            for msg in q.listen():
                if sid not in self.connections:
                    break

                submission = msg['msg']
                msg_type = msg['msg_type']

                sub_classification = submission.get('params', {}).get('classification')
                if sub_classification is None:
                    continue
                if not classification.is_accessible(user_info['classification'], sub_classification):
                    continue

                self.socketio.emit(msg_type, submission, room=sid, namespace=self.namespace)
                LOGGER.info("SocketIO:%s - %s - Sending %s event for submission matching ID: %s",
                            self.namespace, user_info['display'], msg_type, submission['sid'])

                if AUDIT:
                    AUDIT_LOG.info("%s [%s] :: SubmissionMonitoringNamespace.get_submission(sid=%s)",
                                   user_info['uname'], user_info['classification'], submission['sid'])

        except Exception:
            LOGGER.exception(f"SocketIO:{self.namespace} - {user_info['display']}")
        finally:
            LOGGER.info(f"SocketIO:{self.namespace} - {user_info['display']} - Connection to client was terminated")

    @authenticated_only
    def on_monitor(self, data, user_info):

        if ROLES.submission_view not in user_info['roles']:
            LOGGER.warning("SocketIO:%s - %s - User denied access to submission streaming.",
                           self.namespace, user_info['display'])
            return

        LOGGER.info("SocketIO:%s - %s - User as started monitoring submissions...",
                    self.namespace, user_info['display'])

        join_room(user_info['sid'])
        self.socketio.start_background_task(target=self.monitor_submissions, user_info=user_info)

        emit('monitoring', data, room=user_info['sid'], namespace=self.namespace)
