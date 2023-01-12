import logging
import os
import tarfile
from flask import Flask, request, abort
from assemblyline_core.cert_manager import get_server_bundle, get_root_ca_bundle, AL_CERT_DIR, CERT_SERVER_TOKEN
from assemblyline.common import forge
from urllib.parse import urlparse

app = Flask(__name__)

AL_CERT_TAR_DIR = '/etc/assemblyline/ssl_tar/'

# Create directories as necessary
os.makedirs(AL_CERT_TAR_DIR, exist_ok=True)

# Initialize all certificates based on configuration, if necessary
cfg = forge.get_config()

# Initalize encryption for DBs (Datastore, Filestore, Redis)
DBs = [urlparse(host).hostname for host in cfg.datastore.hosts +
       cfg.filestore.archive + cfg.filestore.cache + cfg.filestore.storage] + \
    [cfg.core.redis.nonpersistent.host, cfg.core.redis.persistent.host]

# Initialize encryption for internal AL services
AL_SERVERS = ['service-server', 'internal-ui']

for host in DBs + AL_SERVERS:
    get_server_bundle(host)


# Fetch only the requested server bundle
@app.route("/<server>")
def serve_server_bundle(server):
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')

    server_bundle_tar = os.path.join(AL_CERT_TAR_DIR, f'{server}.tar')
    if not os.path.exists(server_bundle_tar):
        with tarfile.open(server_bundle_tar, 'x:gz') as tar_file:
            [tar_file.add(path, arcname=os.path.basename(path)) for path in get_server_bundle(server)]

    return open(server_bundle_tar, 'rb').read()


# Fetch only the requested server certificate
@app.route("/<server>/crt")
def serve_server_crt(server):
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')
    return open(get_server_bundle(server)[0], 'rb').read()


# Fetch only the requested server private key
@app.route("/<server>/key")
def serve_server_key(server):
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')
    return open(get_server_bundle(server)[1], 'rb').read()


# Fetch only the root bundle used to sign all server certificates
@app.route("/root")
def serve_root_bundle():
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')

    root_bundle_tar = os.path.join(AL_CERT_TAR_DIR, 'root.tar')
    if not os.path.exists(root_bundle_tar):
        with tarfile.open(root_bundle_tar, 'x:gz') as tar_file:
            [tar_file.add(path, arcname=os.path.basename(path)) for path in get_root_ca_bundle()]

    return open(root_bundle_tar, 'rb').read()


# Likely to be used by core components
@app.route("/all")
def serve_all():
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')

    all_bundle_tar = os.path.join(AL_CERT_TAR_DIR, 'all.tar')
    if not os.path.exists(all_bundle_tar):
        with tarfile.open(all_bundle_tar, 'x:gz') as tar_file:
            tar_file.add(AL_CERT_DIR, arcname='')

    return open(all_bundle_tar, 'rb').read()


# Health Check: Instruct other services to be brought up when this server is ready
@app.route("/healthz")
def health_check():
    if request.headers.get('Authorization', '') != f'Bearer {CERT_SERVER_TOKEN}':
        abort(401, 'token refused')

    return app.response_class(status=200 if bool(os.listdir(AL_CERT_DIR)) else 404)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    app.run(host='0.0.0.0', port=8000)
