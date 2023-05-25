"""Federated Lookup

Lookup related data from external systems.

* Provide endpoints to query systems and return links to those results.


Future:

* Provide endpoints to query other systems to enable enrichment of AL data.
"""
import uuid

from flask import request
from requests import Session, exceptions

from assemblyline.odm.models.user import ROLES
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import config, CLASSIFICATION as Classification, LOGGER


SUB_API = "federated_lookup"
federated_lookup_api = make_subapi_blueprint(SUB_API, api_version=4)
federated_lookup_api._doc = "Lookup related data through configured external data sources/systems."


class _Tags():
    """Locally cache supported tags."""

    def __init__(self) -> None:
        self._all_supported_tags = {}
        self.session = Session()

    @property
    def all_supported_tags(self) -> dict[str, dict[str, str]]:
        """Locally cached map of tags each service supports.

        Returns:
        {
            <source name>: {
                <tag name>: <tag classification>,
                ...,
            },
            ...,
        }
        """
        configured_sources = getattr(config.ui, "external_sources", [])
        if len(self._all_supported_tags) != len(configured_sources):
            headers = {
                "accept": "application/json",
            }
            for source in configured_sources:
                # only send requests for sources we haven't cached yet
                if source.name in self._all_supported_tags:
                    continue

                url = f"{source.url}/tags/"
                try:
                    rsp = self.session.get(url, headers=headers, timeout=3.0)
                except exceptions.ConnectionError:
                    # any errors are logged and no result is saved to local cache to enable retry on next query
                    LOGGER.error(f"Unable to connect: {url}")
                    continue
                status_code = rsp.status_code
                if status_code != 200:
                    err = rsp.json()["api_error_message"]
                    LOGGER.error(f"Error from upstream server: {status_code=}, {err=}")
                    continue
                try:
                    data = rsp.json()["api_response"]
                    self._all_supported_tags[source.name] = data
                # noinspection PyBroadException
                except Exception as err:
                    LOGGER.error(f"External API did not return expected format: {err}")
                    continue
        return self._all_supported_tags


# Set global local cache for supported tags
all_supported_tags = _Tags().all_supported_tags


def filtered_tag_names(user):
    """Return the supported tag names of each external service, filtered to what the user has access to."""
    configured_sources = getattr(config.ui, "external_sources", [])
    available_tags = {}
    for source in configured_sources:
        # user cannot know about source
        if user and not Classification.is_accessible(user["classification"], source.classification):
            continue
        # user can view source, now filter tags user cannot see
        available_tags[source.name] = [
            tname for tname, classification in all_supported_tags.get(source.name, {}).items()
            if user and Classification.is_accessible(user["classification"], classification)
        ]
    return available_tags


def log_error(msg, err=None, status_code=None):
    """Log a standard error string, with a unique id reference for logging."""
    err_id = str(uuid.uuid4())
    error = [msg]
    if status_code:
        error.append(f"{status_code=}")
    if err:
        error.append(f"{err=}")
    error.append(f"{err_id}")
    LOGGER.error(" :: ".join(error))
    return err_id


@federated_lookup_api.route("/tags/", methods=["GET"])
@api_login(require_role=[ROLES.external_query])
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
    return make_api_response(filtered_tag_names(user))


@federated_lookup_api.route("/search/<tag_name>/<path:tag>/", methods=["GET"])
@api_login(require_role=[ROLES.external_query])
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
    # this must first be checked against what systems the user is allowed to see
    # additional tag level checking is then done later to provide feedback to user
    available_sources = [
        x for x in getattr(config.ui, "external_sources", [])
        if Classification.is_accessible(user["classification"], x.classification)
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
    errors = {}
    for source in available_sources:
        if tag_name not in all_supported_tags.get(source.name, {}):
            continue
        if not query_sources or source.name in query_sources:
            # check query against the max supported classification of the external system
            # if this is not supported, we should let the user know.
            if not Classification.is_accessible(
                source.max_classification or Classification.UNRESTRICTED,
                tag_classification
            ):
                errors[source.name] = f"Tag classification exceeds max classification of source: {source.name}."
                continue

            # perform the lookup, ensuring access controls are applied
            url = f"{source.url}/search/{tag_name}/{tag}"
            rsp = session.get(url, params=params, headers=headers)
            status_code = rsp.status_code
            if status_code == 404 or status_code == 422:
                # continue searching configured sources if not found or invliad tag.
                continue
            if status_code != 200:
                # as we query across multiple sources, just log errors.
                err_msg = f"Error from source: {source.name}"
                err_id = log_error(err_msg, rsp.json()["api_error_message"], status_code)
                errors[source.name] = f"{err_msg}. Error ID: {err_id}"
                continue
            try:
                data = rsp.json()["api_response"]
                if user and Classification.is_accessible(user["classification"], data["classification"]):
                    links[source.name] = data
            # noinspection PyBroadException
            except Exception as err:
                err_msg = f"{source.name}-proxy did not return a response in the expected format"
                err_id = log_error(err_msg, err)
                errors[source.name] = f"{err_msg}. Error ID: {err_id}"
                continue

    status_code = 200
    if not links:
        status_code = 404
        if errors:
            status_code = 500
    return make_api_response(links, err=errors, status_code=status_code)


# @federated_lookup_api.route("/enrich/<tag_name>/<tag>/", methods=["GET"])
# @api_login(require_role=[ROLES.external_query])
# def enrich_tags(tag_name: str, tag: str, **kwargs):
#    """Search other services for additional information to enrich AL"""
#    pass
