"""Lookup through Malware Bazaar.

"""
import os

from urllib import parse as ul

import requests

from flask import Flask, request


app = Flask(__name__)


MB_VERIFY = os.environ.get("MB_VERIFY", False)
MB_MAX_LIMIT = os.environ.get("MB_MAX_LIMIT", 50)  # Maximum number to return


@app.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
def lookup_ioc(indicator_name: str, ioc: str) -> dict[str, dict[str, str]]:
    """Lookup IOCs from Malware Bazaar.

    MB only has limited support of lookups based on IOCs.
    IOCs submitted must be URL encoded.

    If the IOC is found, a link to view the IOC on Malware Bazaaris returned.

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 5]


    This method should return a dictionary containing:

        {
            "<digest>":  {
                "link": <url to object>,
                "classification": UNRESTRICTED,
            },
        }
    """
    valid_ioc_names = ["hash", "imphash"]
    if indicator_name not in valid_ioc_names:
        return None
    ioc = ul.unquote_plus(ioc)
    if indicator_name == "hash" and len(ioc) not in (32, 40, 64):
        return None

    limit = int(request.args.get("limit", "3"))
    if limit > int(MB_MAX_LIMIT):
        limit = int(MB_MAX_LIMIT)

    max_timeout = request.args.get('max_timeout', "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    session = requests.Session()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    url = "https://mb-api.abuse.ch/api/v1/"
    query = {
        "hash": "get_info",
        "imphash": "get_imphash",
    }[indicator_name]

    data = {
        "query": query,
        indicator_name: ioc,
        "limit": limit,
    }

    rsp = session.post(url, data, headers=headers, verify=MB_VERIFY, timeout=max_timeout)
    if rsp.status_code != 200:
        return None

    rsp_json = rsp.json()
    if rsp_json.get("query_status") != "ok":
        # not found, or invalid data provided
        return None

    # return view links to the gui once we know it's found
    # might be nicer in the future to parse collection results and display them instead?
    data = rsp_json.get("data", [])

    links = {}
    for entity in data:
        digest = entity.get("sha256_hash")
        if digest:
            links[digest] = {
                "link": f"https://bazaar.abuse.ch/sample/{digest}/",
                "classification": "UNRESTRICTED",
            }
    return links


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
