
import logging
import os

from authlib.integrations.flask_client import OAuth
from elasticapm.contrib.flask import ElasticAPM
from flask import Flask
from flask.logging import default_handler

from assemblyline_ui.api.base import api
from assemblyline_ui.api.v4 import apiv4
from assemblyline_ui.api.v4.alert import alert_api
from assemblyline_ui.api.v4.archive import archive_api
from assemblyline_ui.api.v4.authentication import auth_api
from assemblyline_ui.api.v4.bundle import bundle_api
from assemblyline_ui.api.v4.error import error_api
from assemblyline_ui.api.v4.file import file_api
from assemblyline_ui.api.v4.hash_search import hash_search_api
from assemblyline_ui.api.v4.help import help_api
from assemblyline_ui.api.v4.heuristics import heuristics_api
from assemblyline_ui.api.v4.ingest import ingest_api
from assemblyline_ui.api.v4.live import live_api
from assemblyline_ui.api.v4.ontology import ontology_api
from assemblyline_ui.api.v4.result import result_api
from assemblyline_ui.api.v4.replay import replay_api
from assemblyline_ui.api.v4.retrohunt import retrohunt_api
from assemblyline_ui.api.v4.safelist import safelist_api
from assemblyline_ui.api.v4.search import search_api
from assemblyline_ui.api.v4.service import service_api
from assemblyline_ui.api.v4.signature import signature_api
from assemblyline_ui.api.v4.submission import submission_api
from assemblyline_ui.api.v4.submit import submit_api
from assemblyline_ui.api.v4.system import system_api
from assemblyline_ui.api.v4.ui import ui_api
from assemblyline_ui.api.v4.user import user_api
from assemblyline_ui.api.v4.webauthn import webauthn_api
from assemblyline_ui.api.v4.workflow import workflow_api
from assemblyline_ui.error import errors
from assemblyline_ui.healthz import healthz

from assemblyline_ui import config

AL_UNSECURED_UI = os.environ.get('AL_UNSECURED_UI', 'false').lower() == 'true'
CERT_BUNDLE = (
    os.environ.get('UI_CLIENT_CERT_PATH', '/etc/assemblyline/ssl/ui/tls.crt'),
    os.environ.get('UI_CLIENT_KEY_PATH', '/etc/assemblyline/ssl/ui/tls.key')
)
##########################
# App settings
current_directory = os.path.dirname(__file__)
app = Flask("assemblyline_ui")
app.logger.setLevel(60)  # This completely turns off the flask logger
ssl_context = None
if AL_UNSECURED_UI:
    app.config.update(
        SESSION_COOKIE_SECURE=False,
        SECRET_KEY=config.SECRET_KEY,
        PREFERRED_URL_SCHEME='http'
    )
else:
    app.config.update(
        SESSION_COOKIE_SECURE=True,
        SECRET_KEY=config.SECRET_KEY,
        PREFERRED_URL_SCHEME='https'
    )
if all([os.path.exists(fp) for fp in CERT_BUNDLE]):
    # If all files required are present, start up encrypted comms
    ssl_context = CERT_BUNDLE

app.register_blueprint(healthz)
app.register_blueprint(api)
app.register_blueprint(apiv4)
app.register_blueprint(alert_api)
app.register_blueprint(archive_api)
app.register_blueprint(auth_api)
app.register_blueprint(bundle_api)
app.register_blueprint(errors)
app.register_blueprint(error_api)
app.register_blueprint(file_api)
app.register_blueprint(hash_search_api)
app.register_blueprint(help_api)
app.register_blueprint(heuristics_api)
app.register_blueprint(ingest_api)
app.register_blueprint(live_api)
app.register_blueprint(ontology_api)
app.register_blueprint(result_api)
app.register_blueprint(replay_api)
app.register_blueprint(retrohunt_api)
app.register_blueprint(search_api)
app.register_blueprint(service_api)
app.register_blueprint(signature_api)
app.register_blueprint(submission_api)
app.register_blueprint(submit_api)
app.register_blueprint(system_api)
app.register_blueprint(ui_api)
app.register_blueprint(user_api)
app.register_blueprint(webauthn_api)
app.register_blueprint(safelist_api)
app.register_blueprint(workflow_api)


# Setup OAuth providers
if config.config.auth.oauth.enabled:
    providers = []
    for name, p in config.config.auth.oauth.providers.items():
        p = p.as_primitives()
        if p['client_id'] and p['client_secret']:
            # Set provider name
            p['name'] = name

            # Remove AL specific fields
            p.pop('auto_create', None)
            p.pop('auto_sync', None)
            p.pop('user_get', None)
            p.pop('auto_properties', None)
            p.pop('uid_field', None)
            p.pop('uid_regex', None)
            p.pop('uid_format', None)
            p.pop('user_groups', None)
            p.pop('user_groups_data_field', None)
            p.pop('user_groups_name_field', None)
            p.pop('app_provider', None)

            # Add the provider to the list of providers
            providers.append(p)

    if providers:
        oauth = OAuth()
        for p in providers:
            oauth.register(**p)
        oauth.init_app(app)

# Setup logging
app.logger.setLevel(config.LOGGER.getEffectiveLevel())
app.logger.removeHandler(default_handler)
for ph in config.LOGGER.parent.handlers:
    app.logger.addHandler(ph)

# Setup APMs
if config.config.core.metrics.apm_server.server_url is not None:
    app.logger.info(f"Exporting application metrics to: {config.config.core.metrics.apm_server.server_url}")
    ElasticAPM(app, client=config.forge.get_apm_client('al_ui'))


def main():
    wlog = logging.getLogger('werkzeug')
    wlog.setLevel(config.LOGGER.getEffectiveLevel())
    for h in config.LOGGER.parent.handlers:
        wlog.addHandler(h)

    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", debug=False, ssl_context=ssl_context)


if __name__ == '__main__':
    main()
