"""Lookup through Assemblyline.

"""
import concurrent.futures
import json
import os

import requests

from flask import Flask, Response, jsonify, make_response, request

from assemblyline.odm.models import tagging


app = Flask(__name__)


VERIFY = os.environ.get("VERIFY", False)
# We don't need to apply a limit in this query as we already get a count of total results
# and we are not parsing individual results.
MAX_LIMIT = os.environ.get("MAX_LIMIT", 100)
MAX_TMEOUT = os.environ.get("MAX_TIMEOUT", "3")
API_KEY = os.environ.get("API_KEY", "")
# Ensure upstream/downstream system classification is set correctly
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
URL_BASE = os.environ.get("QUERY_URL", "https://assemblyline-ui")

# Mapping of AL tag names to external systems "tag" names
TAG_MAPPING = os.environ.get(
    "TAG_MAPPING",
    dict(
        {tname: tname for tname in tagging.Tagging().flat_fields().keys()},
        md5="md5",
        sha1="sha1",
        sha256="sha256",
        ssdeep="ssdeep",
        tlsh="tlsh",
    )
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


def build_query(tag_name: str, tag: str):
    """Build the tag query string."""
    qry = f'{tag_name}:"{tag}"'
    if tag_name not in ("md5", "sha1", "sha256", "ssdeep", "tlsh"):
        qry = f"result.sections.tags.{qry}"
    return qry


def lookup_tag(tag_name: str, tag: str, limit: int = 25, timeout: float = 3.0):
    """Lookup the tag in Assemblyline.

    Tag values submitted must be URL encoded.

    Complete data from the lookup is returned unmodified.
    """
    if not API_KEY:
        return make_api_response(None, "No API Key is provided. An API Key is required.", 422)

    session = requests.Session()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    search_base = f"{URL_BASE}/api/v4/search"
    qry = build_query(tag_name=tag_name, tag=tag)
    # digests are not tags and cannot be searched for from result index
    url = f"{search_base}/result/"
    if tag_name in ("md5", "sha1", "ssdeep", "tlsh"):
        url = f"{search_base}/file/"

    params = {"query": qry, "rows": min(limit, MAX_LIMIT)}
    rsp = session.get(url, params=params, headers=headers, verify=VERIFY, timeout=timeout)
    rsp_json = rsp.json()

    if rsp.status_code != 200:
        return make_api_response("", rsp_json["api_error_message"], rsp_json["api_status_code"])

    return rsp_json["api_response"]


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

    max_timeout = request.args.get("max_timeout", MAX_TMEOUT)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    data = lookup_tag(tag_name=tn, tag=tag, limit=1)
    if isinstance(data, Response):
        return data
    if not data["total"] or not data["items"]:
        return make_api_response("", "No items found", 404)

    qry = build_query(tn, tag)
    result_link = f"{URL_BASE}/search/result?query={qry}"
    # digests are not tags and cannot be searched for from result index
    if tag_name in ("md5", "sha1", "ssdeep", "tlsh"):
        result_link = f"{URL_BASE}/search/file?query={qry}"

    # default to classification of first returned result...
    # or should we iterate all the returned data and find the minimum?
    classification = data["items"][0]["classification"]

    return make_api_response({
        "link": result_link,
        "count": data["total"],
        "classification": classification,
    })


@app.route("/details/<tag_name>/<path:tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Get detailed lookup results from Assemblyline

    Query Params:
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit       => limit the amount of returned results per source [Default: 25]

    Returns:
    # List of:
    [
        {
            "description": "",                     # Description of the findings
            "malicious": <bool>,                   # Is the file found malicious or not
            "confirmed": <bool>,                   # Is the maliciousness attribution confirmed or not
            "data": {...},                         # Additional Raw data
            "classification": <access control>,    # [Optional] Classification of the returned data
        },
        ...,
    ]
    """
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    limit = int(request.args.get("limit", "25"))
    if limit > int(MAX_LIMIT):
        limit = int(MAX_LIMIT)

    max_timeout = request.args.get("max_timeout", "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    data = lookup_tag(tag_name=tag_name, tag=tag, limit=limit, timeout=max_timeout)
    if isinstance(data, Response):
        return data
    if not data["total"] or not data["items"]:
        return make_api_response("", "No items found", 404)
    items = data["items"]

    # digests are not tags and cannot be searched for from the result index
    # we must do separate queries to this index using the sha256
    if tag_name in ("md5", "sha1", "ssdeep", "tlsh"):
        # de-dupe any possible results
        sha256s = {item["sha256"] for item in items}
        with concurrent.futures.ThreadPoolExecutor(min(32, os.cpu_count() + 4)) as executor:
            future_lookups = [executor.submit(lookup_tag, tag_name="sha256", tag=sha256) for sha256 in sha256s]
            # replace the `file index` result items with the new `result index` items
            items = []
            for future in concurrent.futures.as_completed(future_lookups):
                data = future.result(timeout=max_timeout)
                # TODO: how to handle errors? Just filter out for now.
                items.extend(i for i in data["items"] if not isinstance(i, Response))

    results = [
        {
            "data": item,
            "classification": item["classification"],
            "description": item["id"],
            "confirmed": False,
            "malicious": True if item["result"]["score"] > 999 else False,
        }
        for item in items
    ]

    return make_api_response(results)


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
