"""Example interface for federated lookup plugins/extensions.

Defines the require API required to be implemented in order for federated
lookups to be performed against external systems in Assemblyline.

TODO: Should this be turned into a Blueprint in the main assemblyline-ui code base
and then implmented here? Implementing services would then need to install assemblyline-ui
but they would get access to the various helper functions too which would be nice.
"""
from flask import Flask, Response, jsonify, make_response

app = Flask(__name__)


# supported IOC names
VALID_IOC = []


def make_api_response(data, err: str = "", status_code: int = 200) -> Response:
    """Create a standard response for this API.
    """
    return make_response(
        jsonify({
            "api_response": data,
            "api_error_message": err,
            "api_status_code": status_code,
        }),
        status_code,
    )


@app.route("/ioc/", methods=["GET"])
def get_valid_ioc_names() -> Response:
    """Return valid IOC names supported by this service."""
    return make_api_response(VALID_IOC)


@app.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
def lookup_ioc(indicator_name: str, ioc: str) -> Response:
    """Define how to lookup an indicator in the external system.

    This method should return an api_response containing:

        {
            <identifer/name of object found>:  {
                "link": <url to object>,
                "classification": <access control of the document linked to>,  # Optional
            },
            ...,
        }
    """
    raise NotImplementedError("Not Implemented.")


def main():
    app.run(host="0.0.0.0", port=8000, debug=False)


if __name__ == "__main__":
    main()
