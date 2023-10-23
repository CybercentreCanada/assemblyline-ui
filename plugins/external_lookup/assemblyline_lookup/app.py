"""Lookup through Assemblyline.

"""
import concurrent.futures
import json
import os

from urllib import parse as ul

import requests

from flask import Flask, Response, jsonify, make_response, request

from assemblyline.odm.models import tagging


app = Flask(__name__)


API_KEY = os.environ.get("API_KEY", "")
VERIFY = os.environ.get("VERIFY", True)
MAX_LIMIT = int(os.environ.get("MAX_LIMIT", 100))
MAX_TIMEOUT = float(os.environ.get("MAX_TIMEOUT", 3))
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
        "Content-Type": "application/json",
    }
    search_base = f"{URL_BASE}/api/v4/search"
    qry = build_query(tag_name=tag_name, tag=tag)
    # digests are not tags and cannot be searched for from result index
    url = f"{search_base}/result/"
    if tag_name in ("md5", "sha1", "ssdeep", "tlsh"):
        url = f"{search_base}/file/"

    params = {"query": qry, "rows": min(limit, MAX_LIMIT)}
    rsp = session.post(url, data=params, headers=headers, verify=VERIFY, timeout=timeout)
    rsp_json = rsp.json()

    if rsp.status_code != 200:
        return make_api_response("", rsp_json["api_error_message"], rsp_json["api_status_code"])

    return rsp_json["api_response"]


@app.route("/details/<tag_name>/<tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Get detailed lookup results from Assemblyline

    Variables:
    tag_name => Tag to look up in the external system.
    tag => Tag value to lookup. *Must be double URL encoded.*

    Query Params:
    max_timeout => Maximum execution time for the call in seconds
    limit       => Maximum number of items to return
    nodata      => If specified, do not return the enrichment data

    Returns:
    # List of:
    [
        {
            "description": "",                     # Description of the findings
            "malicious": <bool>,                   # Is the file found malicious or not
            "confirmed": <bool>,                   # Is the maliciousness attribution confirmed or not
            "classification": <access control>,    # [Optional] Classification of the returned data
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "enrichment": [
                {"group": <group>,
                 "name": <name>, "name_description": <description>,
                 "value": <value>, "value_description": <description>,
                },
                ...,
            ]   # [Optional] ordered groupings of additional metadata
        },
        ...,
    ]
    """
    tag = ul.unquote(ul.unquote(tag))
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    enrich = not request.args.get("nodata", "false").lower() in ("true", "1")

    limit = request.args.get("limit", 100, type=int)
    if limit > int(MAX_LIMIT):
        limit = int(MAX_LIMIT)
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = MAX_TIMEOUT

    data = lookup_tag(tag_name=tag_name, tag=tag, limit=limit, timeout=max_timeout)
    if isinstance(data, Response):
        return data
    if not data["total"] or not data["items"]:
        return make_api_response(None, "No results", 200)
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

    results = []
    for item in items:
        sha256, _ = item["id"].split(".", 1)
        r = {
                "count": 1,
                "link":  f"{URL_BASE}/file/detail/{sha256}",
                "classification": item["classification"],
                "description": f"Filetype: {item['type']}. Service: {item['response']['service_name']}.",
                "confirmed": False,
                "malicious": True if item["result"]["score"] > 999 else False,
            }

        if enrich:
            # Future: Any additional info to query that would be useful? Would require a new request though.
            r["enrichment"] = []

        results.append(r)

    return make_api_response(results)


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
