from gevent.monkey import patch_all
patch_all()

from assemblyline_service_server.app import app
