"""Lookup through VirusTotal.

"""
import base64
import hashlib
import os

from urllib import parse as ul

import requests

from flask import Flask, Response, jsonify, make_response, request


app = Flask(__name__)


API_KEY = os.environ.get("VT_API_KEY", "")
VERIFY = os.environ.get("VT_VERIFY", False)
MAX_LIMIT = os.environ.get("VT_MAX_LIMIT", 50)

# supported IOC names
VALID_IOC = ["domain", "hash", "ip-address", "url"]


def make_api_response(data, err: str = "", status_code: int = 200) -> Response:
    """Create a standard response for this API.
    """
    return make_response(
        jsonify({
            "api_response": data,
            "api_error_message": err,
            "api_status_code": status_code,
        }),
        status_code,
    )


@app.route("/ioc/", methods=["GET"])
def get_valid_ioc_names() -> Response:
    """Return valid IOC names supported by this service."""
    return make_api_response(VALID_IOC)


@app.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
def lookup_ioc(indicator_name: str, ioc: str) -> Response:
    """Search for an indicator of compromise on VirusTotal.

    If the IOC is found, a link to view the IOC on VirusTotal is returned.

    IOCs submitted must be URL encoded.

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 5]


    This method should return an api_response containing:

        {
            "vt-<indicator name>":  {
                "link": <url to object>,
                "classification": UNRESTRICTED,
            },
        }
    """
    if indicator_name not in VALID_IOC:
        return make_api_response(
            None,
            f"Invalid indicator name: {indicator_name}. [{', '.join(VALID_IOC)}]",
            400,
        )

    ioc = ul.unquote_plus(ioc)
    if indicator_name == "hash" and len(ioc) not in (32, 40, 64):
        return make_api_response(None, "Invalid hash provided. Require md5, sha1 or sha256", 400)

    limit = int(request.args.get("limit", "3"))
    if limit > int(MAX_LIMIT):
        limit = int(MAX_LIMIT)

    max_timeout = request.args.get("max_timeout", "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    session = requests.Session()
    headers = {
        "accept": "application/json",
        "x-apikey": API_KEY,
    }
    check_url = {
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "ip-address": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "url": f"https://www.virustotal.com/api/v3/urls/{base64.b64encode(ioc)}",
    }[indicator_name]

    rsp = session.get(check_url, headers=headers, verify=VERIFY, timeout=max_timeout)
    if rsp.status_code != 200:
        return make_api_response(rsp.text, "Error submitting data to upstream.", rsp.status_code)

    # return view links to the gui once we know it's found
    view_url = {
        "domain": f"https://www.virustotal.com/gui/domain/{ioc}/summary",
        "hash": f"https://www.virustotal.com/gui/search/{ioc}",
        "ip-address": f"https://www.virustotal.com/gui/ip-address/{ioc}/summary",
        "url": f"https://www.virustotal.com/gui/url/{hashlib.sha256(ioc.encode()).hexdigest()}/summary",
    }[indicator_name]

    return make_api_response({
        f"vt-{indicator_name}": {"link": view_url, "classification": "UNRESTRICTED"}
    })


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
