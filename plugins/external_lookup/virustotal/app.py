"""Lookup through VirusTotal.

"""
import base64
import json
import os

from urllib import parse as ul

import requests

from flask import Flask, Response, jsonify, make_response, request


app = Flask(__name__)


API_KEY = os.environ.get("VT_API_KEY", "")
VERIFY = os.environ.get("VT_VERIFY", False)
MAX_LIMIT = os.environ.get("VT_MAX_LIMIT", 500)
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")  # Classification of this service

# Mapping of AL tag names to external systems "tag" names
TAG_MAPPING = os.environ.get("TAG_MAPPING", {
    "md5": "files",
    "sha1": "files",
    "sha256": "files",
    "network.dynamic.domain": "domains",
    "network.static.domain": "domains",
    "network.dynamic.ip": "ip_addresses",
    "network.static.ip": "ip_addresses",
    "network.dynamic.uri": "urls",
    "network.static.uri": "urls",
})
if not isinstance(TAG_MAPPING, dict):
    TAG_MAPPING = json.loads(TAG_MAPPING)


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


@app.route("/tags/", methods=["GET"])
def get_tag_names() -> Response:
    """Return supported tag names."""
    return make_api_response({tname: CLASSIFICATION for tname in sorted(TAG_MAPPING)})


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str) -> Response:
    """Search for tags on VirusTotal.

    Tags submitted must be URL encoded (not url_plus quoted).

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 1000]


    This method should return an api_response containing:

        {
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "classification": $CLASSIFICATION",
        }
    """
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )

    if tn == "files" and len(tag) not in (32, 40, 64):
        return make_api_response(None, "Invalid hash provided. Require md5, sha1 or sha256", 422)

    limit = int(request.args.get("limit", "500"))
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
    # URLs must be converted into VT "URL identifiers"
    encoded_tag = tag
    if tn == "urls":
        encoded_tag = base64.urlsafe_b64encode(tag.encode()).decode().strip("=")
    check_url = f"https://www.virustotal.com/api/v3/{tn}/{encoded_tag}"

    # ensure there is a result before returning the link, as if you submit a url search
    # to vt that it hasn't seen before, it will start a new scan of that url
    rsp = session.get(check_url, headers=headers, verify=VERIFY, timeout=max_timeout)
    if rsp.status_code == 404:
        return make_api_response(None, "No results.", rsp.status_code)
    elif rsp.status_code != 200:
        return make_api_response(rsp.text, "Error submitting data to upstream.", rsp.status_code)

    # return view links to the gui search once we know it's found
    # note: tag must be double url encoded, and include encoding of `/` for URLs to search correctly.
    search_encoded_tag = ul.quote(ul.quote(tag, safe=''), safe='')
    return make_api_response({
        "link": f"https://www.virustotal.com/gui/search/{search_encoded_tag}",
        "count": 1,  # url/domain/file/ip searches only return a single result/report
        "classification": CLASSIFICATION,
    })


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
