
import os

from assemblyline_client import get_client
from flask import Flask, make_response, jsonify, request

AL_HOST = os.environ.get("AL_HOST", "127.0.0.1.nip.io")
AL_USER = os.environ.get("AL_USER", "admin")
AL_APIKEY = os.environ.get("AL_APIKEY", "devkey:admin")
OBO_HOST = os.environ.get("OBO_HOST", "127.0.0.1.nip.io")
CLIENT = get_client(f"https://{AL_HOST}", apikey=(AL_USER, AL_APIKEY), verify=False)

##########################
# App settings
app = Flask("archiving_hook")
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SECRET_KEY="Not so secret is it?!",
    PREFERRED_URL_SCHEME='https'
)


@app.route("/", methods=["POST"])
def index():
    # Read in the data
    data = request.json

    # TODO: Do stuff here
    metadata = data['metadata'] or {}
    metadata['hook_result'] = "The hook ran successfully!"

    # Ask the API to finally archive the data
    CLIENT._connection.put(f"api/v4/archive/{data['submission']['sid']}/?skip_hook", json=metadata)

    return make_response(jsonify({"success": True}), 200)


def main():
    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", port=5200, debug=False, ssl_context='adhoc')


if __name__ == '__main__':
    main()
