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


@app.route("/details/<tag_name>/<path:tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Define how to search for detailed tag results.

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
    # Invalid tags must either be ignored, or return a 422
    tn = TAG_MAPPING.get(tag_name)
    if tn is None:
        return make_api_response(
            None,
            f"Invalid tag name: {tag_name}. [valid tags: {', '.join(TAG_MAPPING.keys())}]",
            422,
        )

    enrich = not request.args.get("nodata", "false").lower() in ("true", "1")
    max_timeout = request.args.get("max_timeout", MAX_TIMEOUT)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = MAX_TIMEOUT

    raise NotImplementedError("Not Implemented.")


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
