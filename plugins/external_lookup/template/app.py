"""Example interface for federated lookup plugins/extensions.

Defines the require API required to be implemented in order for federated
lookups to be performed against external systems in Assemblyline.

"""
from flask import Flask
app = Flask(__name__)


@app.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
def lookup_ioc(indicator_name: str, ioc: str) -> dict[str, dict[str, str]]:
    """Define how to lookup an indicator in the external system.

    This method should return a dictionary containing:

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
