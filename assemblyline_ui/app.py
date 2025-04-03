import logging
import os

from authlib.integrations.base_client.registry import OAUTH_CLIENT_PARAMS
from authlib.integrations.flask_client import OAuth
from elasticapm.contrib.flask import ElasticAPM
from flask import Flask
from flask.logging import default_handler

from assemblyline_ui.api.base import api
from assemblyline_ui.api.v4 import apiv4
from assemblyline_ui.api.v4.alert import alert_api
from assemblyline_ui.api.v4.apikey import apikey_api
from assemblyline_ui.api.v4.archive import archive_api
from assemblyline_ui.api.v4.assistant import assistant_api
from assemblyline_ui.api.v4.authentication import auth_api
from assemblyline_ui.api.v4.badlist import badlist_api
from assemblyline_ui.api.v4.bundle import bundle_api
from assemblyline_ui.api.v4.error import error_api
from assemblyline_ui.api.v4.federated_lookup import federated_lookup_api
from assemblyline_ui.api.v4.file import file_api
from assemblyline_ui.api.v4.hash_search import hash_search_api
from assemblyline_ui.api.v4.help import help_api
from assemblyline_ui.api.v4.heuristics import heuristics_api
from assemblyline_ui.api.v4.ingest import ingest_api
from assemblyline_ui.api.v4.live import live_api
from assemblyline_ui.api.v4.ontology import ontology_api
from assemblyline_ui.api.v4.proxy import proxy_api
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
THREADED = os.environ.get('THREADED', 'true').lower() == 'true'
AL_SESSION_COOKIE_SAMESITE = os.environ.get("AL_SESSION_COOKIE_SAMESITE", None)
AL_HSTS_MAX_AGE = os.environ.get('AL_HSTS_MAX_AGE', None)
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
if AL_SESSION_COOKIE_SAMESITE:
    if AL_SESSION_COOKIE_SAMESITE in ["Strict", "Lax"]:
        app.config.update(
            SESSION_COOKIE_SAMESITE=AL_SESSION_COOKIE_SAMESITE
        )
    else:
        raise ValueError("AL_SESSION_COOKIE_SAMESITE must be set to 'Strict', 'Lax', or None")

if all([os.path.exists(fp) for fp in CERT_BUNDLE]):
    # If all files required are present, start up encrypted comms
    ssl_context = CERT_BUNDLE
    if AL_HSTS_MAX_AGE is not None:
        try:
            int(AL_HSTS_MAX_AGE)
        except Exception:
            raise ValueError("AL_HSTS_MAX_AGE must be set to an integer")

        def include_hsts_header(response):
            response.headers['Strict-Transport-Security'] = f"max-age={AL_HSTS_MAX_AGE}; includeSubdomains"
            return response

        app.after_request(include_hsts_header)

app.register_blueprint(healthz)
app.register_blueprint(api)
app.register_blueprint(apiv4)
app.register_blueprint(alert_api)
if config.config.datastore.archive.enabled:
    app.register_blueprint(archive_api)
if config.AI_AGENT.has_backends():
    app.register_blueprint(assistant_api)
app.register_blueprint(apikey_api)
app.register_blueprint(auth_api)
app.register_blueprint(badlist_api)
app.register_blueprint(bundle_api)
app.register_blueprint(errors)
app.register_blueprint(error_api)
app.register_blueprint(federated_lookup_api)
app.register_blueprint(file_api)
app.register_blueprint(hash_search_api)
app.register_blueprint(help_api)
app.register_blueprint(heuristics_api)
app.register_blueprint(ingest_api)
app.register_blueprint(live_api)
app.register_blueprint(ontology_api)
if len(config.config.ui.api_proxies) > 0:
    app.register_blueprint(proxy_api)
app.register_blueprint(result_api)
if config.config.ui.allow_replay:
    app.register_blueprint(replay_api)
if config.config.retrohunt.enabled:
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

        client_id = p.get('client_id', None)
        client_secret = p.get('client_secret', None)

        if client_id:
            # Remove AL specific fields safely using pop with default to None
            # as those fields will end up being sent as metadata
            safe_fields = set(list(OAUTH_CLIENT_PARAMS) + ["jwks_uri"])
            for field in list(p.keys()):
                if field not in safe_fields:
                    p.pop(field, None)

            # Set provider name
            p['name'] = name

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

# Check download encoding config setting
if config.DOWNLOAD_ENCODING == "raw" and not config.ALLOW_RAW_DOWNLOADS:
    raise ValueError("Incompatible download_encoding selected: \"raw\" cannot be selected with allow_raw_downloads set to False.")
if config.DOWNLOAD_ENCODING == "zip" and not config.ALLOW_ZIP_DOWNLOADS:
    raise ValueError("Incompatible download_encoding selected: \"zip\" cannot be selected with allow_zip_downloads set to False.")

def main():
    wlog = logging.getLogger('werkzeug')
    wlog.setLevel(config.LOGGER.getEffectiveLevel())
    for h in config.LOGGER.parent.handlers:
        wlog.addHandler(h)

    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", debug=False, ssl_context=ssl_context, threaded=THREADED)


if __name__ == '__main__':
    main()
