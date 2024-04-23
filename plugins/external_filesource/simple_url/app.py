"""Fetch a file using Python requests

"""
import os

import requests

from flask import Flask, Response, jsonify, make_response, request

app = Flask(__name__)


API_KEY = os.environ.get("API_KEY", "")
MAX_LIMIT = int(os.environ.get("MAX_LIMIT", 100))
MAX_TIMEOUT = float(os.environ.get("MAX_TIMEOUT", 3))
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
URL_BASE = os.environ.get("QUERY_URL", "https://assemblyline-ui")

# verify can be boolean or path to CA file
verify = str(os.environ.get("VERIFY", "true")).lower()
if verify in ("true", "1"):
    verify = True
elif verify in ("false", "0"):
    verify = False
VERIFY = verify


def make_api_response(data, err: str = "", status_code: int = 200) -> Response:
    """Create a standard response for this API."""
    return make_response(
        jsonify({
            "api_response": data,
            "api_error_message": err,
            "api_status_code": status_code,
        }),
        status_code,
    )



@app.route("/fetch/", methods=["GET"])
def fetch_file() -> Response:
    """Fetch the file corresponding with the `url` parameter

    Variables:
    None

    Query Params:
    url => URL to fetch

    Returns:
    <THE RAW FILE BINARY>
    """
    url = request.args.get('url', None)
    if not url:
        return make_api_response(data="", status_code=404)

    return requests.get(url).content


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
