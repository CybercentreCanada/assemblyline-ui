
import jwt

from assemblyline_client import get_client
from flask import Flask, render_template, request, redirect

TOKEN = None
CLIENT = get_client("https://localhost", auth=('admin', 'admin'), verify=False)

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

    return render_template("index.html", user=whoami['username'], server=request.host[:-5],
                           error=error, token_headers=headers)


def main():
    app.jinja_env.cache = {}
    app.run(host="0.0.0.0", port=5100, debug=False, ssl_context='adhoc')


if __name__ == '__main__':
    main()
