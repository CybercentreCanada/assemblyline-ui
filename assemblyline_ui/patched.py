from gevent.monkey import patch_all
patch_all()

from assemblyline_ui.app import app
