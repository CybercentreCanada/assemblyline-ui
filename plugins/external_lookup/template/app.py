"""Example interface for federated lookup plugins/extensions.

Defines the require API required to be implemented in order for federated
lookups to be performed against external systems in Assemblyline.

These implemented microservices are responsible for translating the AL tags into the
correct lookups for the external services.

To allow for extended use by non-AL systems, these tag mappings should also be configurable.
"""
import json
import os

from flask import Flask, Response, jsonify, make_response

app = Flask(__name__)


# Classification of this service
CLASSIFICATION = os.environ.get("CLASSIFICATION", "TLP:CLEAR")
# Mapping of AL tag names to external systems "tag" names
# eg: {"network.dynamic.ip": "ip-address", "network.static.ip": "ip-address"}
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
def get_tag_names() -> Response:
    """Return supported tag names."""
    return make_api_response(sorted(TAG_MAPPING))


@app.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
def search_tag(tag_name: str, tag: str) -> Response:
    """Define how to lookup a tag in the external system.

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
    raise NotImplementedError("Not Implemented.")


@app.route("/details/<tag_name>/<path:tag>/", methods=["GET"])
def tag_details(tag_name: str, tag: str) -> Response:
    """Define how to search for detailed tag results.

    Result output should conform to the following:
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
    raise NotImplementedError("Not Implemented.")


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
