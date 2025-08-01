try:
    from gevent.monkey import patch_all
    patch_all()
except ImportError:
    patch_all = None

import logging
import os
from datetime import timedelta

from flask import Flask
from flask_socketio import SocketIO

from assemblyline.common import forge
from assemblyline.common import log as al_log
from assemblyline_ui.healthz import healthz
from assemblyline_ui.sio.alert import AlertMonitoringNamespace
from assemblyline_ui.sio.file import FileCommentNamespace
from assemblyline_ui.sio.live_submission import LiveSubmissionNamespace
from assemblyline_ui.sio.retrohunt import RetrohuntNamespace
from assemblyline_ui.sio.status import SystemStatusNamespace
from assemblyline_ui.sio.submission import SubmissionMonitoringNamespace

CERT_BUNDLE = (
    os.environ.get('SIO_CLIENT_CERT_PATH', '/etc/assemblyline/ssl/sio/tls.crt'),
    os.environ.get('SIO_CLIENT_KEY_PATH', '/etc/assemblyline/ssl/sio/tls.key')
)

config = forge.get_config()

# Prepare the logger
al_log.init_logging("ui")
LOGGER = logging.getLogger('assemblyline.ui.socketio')
LOGGER.info("SocketIO server ready to receive connections...")

# Prepare the app
app = Flask('socketio')
# Update app config with common settings
app.config.update(
    SECRET_KEY=config.ui.secret_key,
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME=timedelta(seconds=config.ui.session_duration),
)
app.register_blueprint(healthz)

# If the environment says we should prefix our app by something, do so
if 'APPLICATION_ROOT' in os.environ:
    LOGGER.info(f"Flask application root changing: {os.environ['APPLICATION_ROOT']}")
    app.config['APPLICATION_ROOT'] = os.environ['APPLICATION_ROOT']
    app.config['SESSION_COOKIE_PATH'] = '/'

# NOTE: we need to run in threading mode while debugging otherwise, use gevent
socketio = SocketIO(app, async_mode=os.environ.get('ASYNC_MODE', 'gevent'), cors_allowed_origins='*')

# Loading the different namespaces
socketio.on_namespace(AlertMonitoringNamespace('/alerts'))
socketio.on_namespace(FileCommentNamespace('/file_comments'))
socketio.on_namespace(LiveSubmissionNamespace('/live_submission'))
socketio.on_namespace(SubmissionMonitoringNamespace('/submissions'))
socketio.on_namespace(RetrohuntNamespace('/retrohunt'))
socketio.on_namespace(SystemStatusNamespace('/status'))


if __name__ == '__main__':
    log_level = al_log.log_level_map.get(config.logging.log_level, 60) if config.ui.debug else 60

    # Set the log level for the app and werkzeug
    app.logger.setLevel(log_level)
    wlog = logging.getLogger('werkzeug')
    wlog.setLevel(log_level)
    # Run debug mode
    if all([os.path.exists(fp) for fp in CERT_BUNDLE]):
        # If all files required are present, start up encrypted comms
        socketio.run(app, host="0.0.0.0", port=5002, keyfile=CERT_BUNDLE[1], certfile=CERT_BUNDLE[0])
    else:
        socketio.run(app, host="0.0.0.0", port=5002)
