"""Lookup through Assemblyline.

"""
import json
import os

import requests

from flask import Flask, Response, jsonify, make_response, request

from assemblyline.odm.models import tagging


app = Flask(__name__)


VERIFY = os.environ.get("MB_VERIFY", False)
# We don't need to apply a limit in this query as we already get a count of total results
# and we are not parsing individual results.
MAX_LIMIT = 1
MAX_TMEOUT = os.environ.get("MAX_TIMEOUT", "3")
API_KEY = os.environ.get("API_KEY", "")
# Ensure upstream/downstream system classification is set correctly
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
URL_BASE = os.environ.get("QUERY_URL", "https://assemblyline-ui")

# Mapping of AL tag names to external systems "tag" names
TAG_MAPPING = os.environ.get(
    "TAG_MAPPING",
    dict({tname: tname for tname in tagging.Tagging().flat_fields().keys()}, md5="md5", sha1="sha1", sha256="sha256")
)
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
    # This is the minimum classification of the tag name, not the tag value.
    return make_api_response({tname: CLASSIFICATION for tname in sorted(TAG_MAPPING)})


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str):
    """Lookup tags from upstream/downstream assemblyline

    Tag values submitted must be URL encoded.

    Arguments: (optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]


    This method should return an api_response containing:

        {
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "classification": <classification of search>,  # Should this be the max
        }
    """
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    if tn in ("md5", "sha1", "sha256") and len(tag) not in (32, 40, 64):
        return make_api_response("", "Invalid hash provided. Require md5, sha1 or sha256", 422)

    max_timeout = request.args.get("max_timeout", MAX_TMEOUT)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    session = requests.Session()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }

    search_base = f"{URL_BASE}/api/v4/search"
    url = f"{search_base}/result/"
    qry = f'result.sections.tags.{tn}:"{tag}"'
    result_link = f"{URL_BASE}/search/result?query={qry}"
    # Return default classification of the upstream instance for tags
    # or should we retrieve multiple and parse the returned data and find one more accurate than the minimum?
    classification = CLASSIFICATION

    # digests are not tags and have their own dedicate lookup
    if tn in ("md5", "sha1", "sha256"):
        url = f"{search_base}/file/{tag}/"
        qry = tag
        result_link = f"{URL_BASE}/search/file?query={qry}"

    params = {"query": qry, "rows": MAX_LIMIT}
    rsp = session.get(url, params=params, headers=headers, verify=VERIFY, timeout=max_timeout)
    rsp_json = rsp.json()
    if rsp.status_code != 200:
        return make_api_response("", rsp_json["api_error_message"], rsp_json["api_status_code"])
    data = rsp_json["api_response"]

    if not data["total"] or not data["items"]:
        return make_api_response("", "No items found", 404)

    # we can get a more accurate classification for file search
    if tn in ("md5", "sha1", "sha256"):
        items = data["items"]
        if items:
            classification = items[0]["classification"]

    return make_api_response({
        "link": result_link,
        "count": data["total"],
        "classification": classification,
    })


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
