import logging

from flask import Flask
from flask_socketio import SocketIO

from al_ui.socketio.alert import AlertMonitoringNamespace
from al_ui.socketio.live_submission import LiveSubmissionNamespace
from assemblyline.common import forge, log as al_log

config = forge.get_config()

app = Flask(__name__)
app.config['SECRET_KEY'] = config.ui.secret_key
socketio = SocketIO(app)

al_log.init_logging("ui")
LOGGER = logging.getLogger('assemblyline.ui.socketio')


if __name__ == '__main__':
    # This is needed for background tasks to work
    from eventlet import monkey_patch
    monkey_patch()
    # END of Background tasks monkey_patch...

    # Loading the different namespaces
    socketio.on_namespace(AlertMonitoringNamespace('/alerts'))
    socketio.on_namespace(LiveSubmissionNamespace('/live_submission'))

    LOGGER.info("SocketIO server ready to receive connections...")
    socketio.run(app, host="0.0.0.0", port=5002, debug=config.ui.debug)
