
import jwt
import os

from assemblyline_client import get_client
from flask import Flask, render_template, request, redirect

TOKEN = None
AL_HOST = os.environ.get("AL_HOST", "127.0.0.1.nip.io")
AL_USER = os.environ.get("AL_USER", "admin")
AL_APIKEY = os.environ.get("AL_APIKEY", "devkey:admin")
OBO_HOST = os.environ.get("OBO_HOST", "127.0.0.1.nip.io")
CLIENT = get_client(f"https://{AL_HOST}", apikey=(AL_USER, AL_APIKEY), verify=False)

##########################
# App settings
app = Flask("obo_test")
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SECRET_KEY="Not so secret is it?!",
    PREFERRED_URL_SCHEME='https'
)


@app.route("/token/", methods=["GET"])
def get_token():
    global TOKEN
    TOKEN = request.values.get("token")
    return redirect("/")


@app.route("/", methods=["GET"])
def index():
    global TOKEN
    error = None
    headers = {}
    whoami = None

    if TOKEN:
        try:
            whoami = CLIENT._connection.get("api/v4/user/whoami/", headers={"Authorization": f"Bearer {TOKEN}"})
            headers = jwt.get_unverified_header(TOKEN)
        except Exception as e:
            # Token is invalid call whoami without token
            TOKEN = None
            error = str(e)

    if not whoami:
        whoami = CLIENT._connection.get("api/v4/user/whoami/")

    return render_template("index.html", user=whoami['username'], al_server=AL_HOST, obo_server=OBO_HOST,
                           al_user=AL_USER, error=error, token_headers=headers)


def main():
    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", port=5100, debug=False, ssl_context='adhoc')


if __name__ == '__main__':
    main()
