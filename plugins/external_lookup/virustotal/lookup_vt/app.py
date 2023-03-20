"""Lookup through VirusTotal.

"""
import base64
import hashlib
import os

from urllib import parse as ul

import requests

from flask import Flask, request


app = Flask(__name__)


VT_API_KEY = os.environ.get("VT_API_KEY", "")
VT_VERIFY = os.environ.get("VT_VERIFY", False)
VT_MAX_LIMIT = os.environ.get("VT_MAX_LIMIT", 50)


@app.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
def lookup_ioc(indicator_name: str, ioc: str) -> dict[str, dict[str, str]]:
    """Search for an indicator of compromise on VirusTotal.

    If the IOC is found, a link to view the IOC on VirusTotal is returned.

    IOCs submitted must be URL encoded.

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 5]


    This method should return a dictionary containing:

        {
            "vt-<indicator name>":  {
                "link": <url to object>,
                "classification": UNRESTRICTED,
            },
        }
    """
    valid_ioc_names = ["domain", "hash", "ip-address", "url"]
    if indicator_name not in valid_ioc_names:
        return None
    ioc = ul.unquote_plus(ioc)
    if indicator_name == "hash" and len(ioc) not in (32, 40, 64):
        return None

    limit = int(request.args.get("limit", "3"))
    if limit > int(VT_MAX_LIMIT):
        limit = int(VT_MAX_LIMIT)

    max_timeout = request.args.get("max_timeout", "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    session = requests.Session()
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY,
    }

    check_url = {
        "domain": f"https://www.virustotal.com/api/v3/domains/{ioc}",
        "hash": f"https://www.virustotal.com/api/v3/files/{ioc}",
        "ip-address": f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}",
        "url": f"https://www.virustotal.com/api/v3/urls/{base64.b64encode(ioc)}",
    }.get(indicator_name)
    if not check_url:
        return None

    rsp = session.get(check_url, headers=headers, verify=VT_VERIFY, timeout=max_timeout)
    if rsp.status_code != 200:
        return None

    # return view links to the gui once we know it's found
    view_url = {
        "domain": f"https://www.virustotal.com/gui/domain/{ioc}/summary",
        "hash": f"https://www.virustotal.com/gui/search/{ioc}",
        "ip-address": f"https://www.virustotal.com/gui/ip-address/{ioc}/summary",
        "url": f"https://www.virustotal.com/gui/url/{hashlib.sha256(ioc.encode()).hexdigest()}/summary",
    }[indicator_name]

    return {
        f"vt-{indicator_name}": {"link": view_url, "classification": "UNRESTRICTED"}
    }


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
