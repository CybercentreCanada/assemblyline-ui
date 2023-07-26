"""Example interface for federated lookup plugins/extensions.

Defines the require API required to be implemented in order for federated
lookups to be performed against external systems in Assemblyline.

These implemented microservices are responsible for translating the AL tags into the
correct lookups for the external services.

To allow for extended use by non-AL systems, these tag mappings should also be configurable.
"""
import json
import os

from flask import Flask, Response, jsonify, make_response, request

app = Flask(__name__)


# Classification of this service
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
# Mapping of AL tag names to external systems "tag" names
# eg: {"network.dynamic.ip": "ip-address", "network.static.ip": "ip-address"}
TAG_MAPPING = os.environ.get("TAG_MAPPING", {})
if not isinstance(TAG_MAPPING, dict):
    TAG_MAPPING = json.loads(TAG_MAPPING)
# Default settings
MAX_LIMIT = int(os.environ.get("MAX_LIMIT", 100))
MAX_TIMEOUT = float(os.environ.get("MAX_TIMEOUT", 3))


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
    return make_api_response(sorted(TAG_MAPPING))


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str) -> Response:
    """Define how to lookup a tag in the external system.

    Query Params:
    max_timeout => Maximum execution time for the call in seconds
    limit       => Maximum number of items to return

    This method should return an api_response containing:

        {
            "link": <url to search results in external system>,
            "count": <count of results from the external system>,
            "classification": <access control of the document linked to>,  # Optional
        }
    """
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )
    limit = min(request.args.get("limit", MAX_LIMIT, type=int), MAX_LIMIT)
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT, type=float)
    raise NotImplementedError("Not Implemented.")


@app.route("/details/<tag_name>/<path:tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Define how to search for detailed tag results.

    Query Params:
    max_timeout => Maximum execution time for the call in seconds
    limit       => Maximum number of items to return
    enrich      => If specified, return semi structured Key:Value pairs of additional metadata under "enrichment"

    Result output should conform to the following:
    # List of:
    [
        {
            "description": "",                     # Description of the findings
            "malicious": <bool>,                   # Is the file found malicious or not
            "confirmed": <bool>,                   # Is the maliciousness attribution confirmed or not
            "data": {...},                         # Additional Raw data
            "classification": <access control>,    # [Optional] Classification of the returned data
            "enrichment": [{name: <name>, value: <value>}, ...}   # [Optional] list of pairs of additional metadata
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

    limit = min(request.args.get("limit", MAX_LIMIT, type=int), MAX_LIMIT)
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT, type=float)
    enrich = request.args.get("enrich", "false").lower() in ("true", "1")

    raise NotImplementedError("Not Implemented.")


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
