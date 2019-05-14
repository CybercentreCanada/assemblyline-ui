try:
    from gevent.monkey import patch_all
    patch_all()
except ImportError:
    patch_all = None

import logging

from flask import Flask
from flask_socketio import SocketIO

from al_ui.sio.alert import AlertMonitoringNamespace
from al_ui.sio.live_submission import LiveSubmissionNamespace
from al_ui.sio.status import SystemStatusNamespace
from al_ui.sio.submission import SubmissionMonitoringNamespace
from assemblyline.common import forge, log as al_log

config = forge.get_config()

# Prepare the logger
al_log.init_logging("ui")
LOGGER = logging.getLogger('assemblyline.ui.socketio')
LOGGER.info("SocketIO server ready to receive connections...")

# Prepare the app
app = Flask(__name__)
app.config['SECRET_KEY'] = config.ui.secret_key
# NOTE: we need to run in threading mode while debugging otherwise, use gevent
socketio = SocketIO(app, async_mode="gevent" if not config.ui.debug else "threading")

# Loading the different namespaces
socketio.on_namespace(AlertMonitoringNamespace('/alerts'))
socketio.on_namespace(LiveSubmissionNamespace('/live_submission'))
socketio.on_namespace(SubmissionMonitoringNamespace('/submissions'))
socketio.on_namespace(SystemStatusNamespace('/status'))

if __name__ == '__main__':
    # Run debug mode
    socketio.run(app, host="0.0.0.0", port=5002, debug=config.ui.debug)
