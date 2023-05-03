"""Federated Lookup

Lookup related data from external systems.

* Provide endpoints to query systems and return links to those results.


Future:

* Provide endpoints to query other systems to enable enrichment of AL data.
"""
from flask import request
from requests import Session, exceptions

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import config, CLASSIFICATION as Classification, LOGGER


SUB_API = "federated_lookup"
federated_lookup_api = make_subapi_blueprint(SUB_API, api_version=4)
federated_lookup_api._doc = "Lookup related data through configured external data sources/systems."


def _get_tag_names(user, max_timeout=3.0):
    """Get the supported tag names of each external service.

    This function is for internal use without the login and routing wrappers.
    """
    # validate what sources the user is allowed to know about
    available_sources = [
        x for x in config.ui.external_sources
        if Classification.is_accessible(user["classification"], x.classification)
    ]

    session = Session()
    headers = {
        "accept": "application/json",
    }

    results = {}
    for source in available_sources:
        url = f"{source.url}/tags/"
        try:
            rsp = session.get(url, headers=headers, timeout=max_timeout)
        except exceptions.ConnectionError:
            # since this get's called from /whoami, we don't want a service going down to prevent user logins
            LOGGER.error(f"Unable to connect: {url}")
            continue
        status_code = rsp.status_code
        if status_code != 200:
            # assume service unavailable, look for others
            err = rsp.json()["api_error_message"]
            LOGGER.error(f"Error from upstream server: {status_code=}, {err=}")
            continue
        try:
            data = rsp.json()["api_response"]
            results[source.name] = [
                tname for tname, classification in data.items()
                if user and Classification.is_accessible(user["classification"], classification)
            ]
        # noinspection PyBroadException
        except Exception as err:
            LOGGER.error(f"External API did not return expected format: {err}")
            continue
    return results


@federated_lookup_api.route("/tags/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def get_tag_names(**kwargs):
    """Return the supported tags of each external service.

    Arguments: (optional)
    max_timeout     => Maximum execution time for the call in seconds [Default: 3 seconds]

    Data Block:
    None

    API call examples:
    /api/v4/federated_lookup/tags/

    Returns:
    A dictionary of sources with their supported tags.

    Result example:
    {                           # Dictionary of:
        <source_name>: [
            <tag name>,
            <tag name>,
            ...,
        ],
        ...,
    }
    """
    user = kwargs["user"]
    max_timeout = request.args.get("max_timeout", "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0
    return make_api_response(_get_tag_names(user, max_timeout))


@federated_lookup_api.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def search_tags(tag_name: str, tag: str, **kwargs):
    """Search AL tags across all configured external sources/systems.

    Variables:
    tag_name => Tag to look up in the external system.
    tag => Tag value to lookup. Must be URL encoded.

    Arguments: (optional)
    classification  => Classification of the tag [Default: minimum configured classification]
    sources         => | separated list of data sources. If empty, all configured sources are used.
    max_timeout     => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit           => limit the amount of returned results counted per source [Default: 500]

    Data Block:
    None

    API call examples:
    /api/v4/federated_lookup/search/url/http%3A%2F%2Fmalicious.domain%2Fbad/
    /api/v4/federated_lookup/search/url/http%3A%2F%2Fmalicious.domain%2Fbad/?sources=virustotal|malware_bazar

    Returns:
    A dictionary of sources with links to found samples.

    Result example:
    {                           # Dictionary of:
        <source_name>: {
            "link": <https link to results>,
            "count": <number of hits from search>,
            "classification": <classification of search>,
        },
        ...,
    }
    """
    user = kwargs["user"]
    query_sources = request.args.get("sources")
    if query_sources:
        query_sources = query_sources.split("|")

    max_timeout = request.args.get("max_timeout", "3")
    limit = request.args.get("limit", "500")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    tag_classification = request.args.get("classification", Classification.UNRESTRICTED)

    # validate what sources the user is allowed to submit requests to.
    # this must be checked against what systems the user is allowed to see
    # as well as the the max supported classification of the external system
    available_sources = [
        x for x in config.ui.external_sources
        if Classification.is_accessible(user["classification"], x.classification)
        and Classification.is_accessible(x.max_classification or Classification.UNRESTRICTED, tag_classification)
    ]

    session = Session()
    headers = {
        "accept": "application/json",
    }
    params = {
        "limit": limit,
        "max_timeout": max_timeout,
    }

    links = {}
    for source in available_sources:
        if not query_sources or source.name in query_sources:
            # perform the lookup, ensuring access controls are applied
            url = f"{source.url}/search/{tag_name}/{tag}"
            rsp = session.get(url, params=params, headers=headers)
            status_code = rsp.status_code
            if status_code == 404:
                # continue searching configured sources if not found.
                continue
            if status_code != 200:
                # as we query across multiple sources, just log errors.
                err = rsp.json()["api_error_message"]
                LOGGER.error(f"Error from upstream server: {status_code=}, {err=}")
                continue
            try:
                data = rsp.json()["api_response"]
                if user and Classification.is_accessible(user["classification"], data["classification"]):
                    links[source.name] = data
            # noinspection PyBroadException
            except Exception as err:
                LOGGER.error(f"External API did not return expected format: {err}")
                continue

    return make_api_response(links)


# @federated_lookup_api.route("/enrich/<tag_name>/<tag>/", methods=["GET"])
# @api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
# def enrich_tags(tag_name: str, tag: str, **kwargs):
#    """Search other services for additional information to enrich AL"""
#    pass
