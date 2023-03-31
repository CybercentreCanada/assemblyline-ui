"""Lookup through Malware Bazaar.

"""
import json
import os

import requests

from flask import Flask, Response, jsonify, make_response, request


app = Flask(__name__)


VERIFY = os.environ.get("MB_VERIFY", False)
MAX_LIMIT = os.environ.get("MB_MAX_LIMIT", 500)  # Maximum number to return

API_KEY = os.environ.get("API_KEY", "")
# Ensure upstream/downstream system classification is set correctly
CLASSIFICATION = os.environ.get("CLASSIFICATION", "UNRESTRICTED")
QUERY_URL = os.environ.get("QUERY_URL", "https://assemblyline-ui")

# Mapping of AL tag names to external systems "tag" names
TAG_MAPPING = os.environ.get("TAG_MAPPING", {})
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
def get_tag_mappings() -> Response:
    """Return tag mappings upported by this service."""
    return make_api_response(TAG_MAPPING)


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str):
    """Lookup tags from upstream/downstream assemblyline

    Tag values submitted must be URL encoded.

    Arguments: (optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 500]


    This method should return an api_response containing:

        {
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "classification": <classification of search>,  # Should this be the max
        }
    """
    # since this is AL to AL mappings, if no TAG_MAPPINGS are given, assume tags are
    # already in the correct format
    tn = tag_name
    if TAG_MAPPING:
        tn = TAG_MAPPING.get(tag_name)
        if tn is None:
            return make_api_response(
                None,
                f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
                400,
            )

    limit = int(request.args.get("limit", "1000"))
    if limit > int(MAX_LIMIT):
        limit = int(MAX_LIMIT)

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

    url = f"{QUERY_URL}/api/v4/"
    rsp = session.get(url, headers=headers, verify=VERIFY, timeout=max_timeout)

    rsp_json = rsp.json()

    # return view links to the gui once we know it's found
    data = rsp_json.get("data", [])

    return make_api_response({
        "link": f"",
        "count": len(data),
        "classification": "",
    })


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
