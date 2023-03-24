"""Federated Lookup

Lookup related data from external systems. Data could include:

* IOCs
* Hashes
* Others?

"""
import requests
from flask import request

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import config, CLASSIFICATION as Classification


SUB_API = "federated_lookup"
federated_lookup_api = make_subapi_blueprint(SUB_API, api_version=4)
federated_lookup_api._doc = "Lookup related data through configured external data sources/systems."


@federated_lookup_api.route("/ioc/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def get_valid_indicator_names(**kwargs):
    """Return all valid IOC names for all configured sources."""
    print("CALLED")

    return make_api_response(["TODO"])


@federated_lookup_api.route("/ioc/<indicator_name>/<ioc>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def search_ioc(indicator_name: str, ioc: str, **kwargs):
    """
    Search for an Indicator of Compromise across all configured external sources/systems.

    Variables:
    indicator_name => specify the name of the indicator being looked up in the external system.
    ioc => IOC to lookup. Must be URL encoded.

    Arguments:(optional)
    max_timeout => Maximum execution time for the call in seconds [Default: 3 seconds]
    sources     => | separated list of data sources [Default: all]
    limit       => limit the amount of returned results per source [Default: 5]

    Data Block:
    None

    API call examples:
    /api/v4/federated_lookup/url/http%3A%2F%2Fmalicious.domain%2Fbad/
    /api/v4/federated_lookup/url/http%3A%2F%2Fmalicious.domain%2Fbad/?sources=virustotal|malware_bazar

    Returns:
    A dictionary of sources with links to found samples.

    Result example:
    {                           # Dictionary of:
        <source_name>: [
            {<name>: <https link to results>},
            ...,
        ],
        ...,
    }
    """
    print(f"GOT: {indicator_name=}, {ioc=}")
    user = kwargs['user']
    sources = request.args.get("sources", "all")

    max_timeout = request.args.get('max_timeout', "3")
    limit = request.args.get('limit', "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    available_sources = [
        x for x in config.ui.external_sources
        if Classification.is_accessible(user['classification'], x.classification)
    ]
    print(f"*** {available_sources=}")

    session = requests.Session()
    headers = {
        "accept": "application/json",
    }
    params = {
        "limit": limit,
        "max_timeout": max_timeout,
    }

    links = {}
    for source, in available_sources:
        if sources == "all" or source.name in sources:
            # perform the lookup, ensuring access controls are applied
            url = f"{source.url}/ioc/{indicator_name}/{ioc}"
            print(f"{url=}")
            res = session.get(url, params=params, headers=headers)
            if res.status_code != 200:
                # as we query across multiple sources, just skip both errors and not found?
                continue
            for name, details in res.items():
                if user and Classification.is_accessible(user['classification'], details['classification']):
                    links.setdefault(source.name, []).append({name: details["link"]})
    return make_api_response(links)
