"""Federated Lookup

Lookup related data from external systems.

* Provide endpoints to query systems and return links to those results.
* Provide endpoints to query other systems to enable enrichment of AL data.
"""
import concurrent.futures
import os
import uuid

from typing import TypedDict
from urllib import parse as ul

from flask import request
from requests import Session, exceptions

from assemblyline.common.threading import APMAwareThreadPoolExecutor
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


def parse_qp(request, limit: int = 100, timeout: float = 5.0):
    """Parse the standard query params."""
    query_sources = request.args.get("sources")
    if query_sources:
        query_sources = query_sources.split("|")

    max_timeout = request.args.get("max_timeout", timeout)
    limit = request.args.get("limit", limit, type=int)
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = timeout

    tag_classification = request.args.get("classification", Classification.UNRESTRICTED)

    return {
        "query_sources": query_sources,
        "max_timeout": max_timeout,
        "limit": limit,
        "tag_classification": tag_classification,
    }


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


def query_external(
    query_type,
    user,
    source,
    tag_name: str,
    tag: str,
    tag_classification: str,
    limit: int,
    timeout: float,
) -> TypedDict("QueryResult", {"error": str, "items": list}):
    """Query the external source for details."""
    if tag_name not in all_supported_tags.get(source.name, {}):
        return

    result = {
        "error": "",
        "items": [],
    }
    # check query against the max supported classification of the external system
    # if this is not supported, we should let the user know.
    if not Classification.is_accessible(
        source.max_classification or Classification.UNRESTRICTED,
        tag_classification
    ):
        result["error"] = f"Tag classification exceeds max classification of source: {source.name}."
        return result

    # perform the lookup, ensuring access controls are applied
    session = Session()
    headers = {
        "accept": "application/json",
    }
    params = {
        "limit": limit,
        "max_timeout": timeout,
    }
    if query_type != "details":
        params["nodata"] = True

    url = f"{source.url}/{query_type}/{tag_name}/{tag}/"
    rsp = session.get(url, params=params, headers=headers)

    status_code = rsp.status_code
    if status_code == 404 or status_code == 422:
        result["error"] = "Not Found"
    elif status_code != 200:
        try:
            err_msg = rsp.json()["api_error_message"]
        except exceptions.JSONDecodeError:
            err_msg = f"{source.name}-proxy experienced an unknown error"
        err_id = log_error(f"Error from {source.name}", err_msg, status_code)
        result["error"] = f"{err_msg}. Error ID: {err_id}"
    else:
        try:
            api_response = rsp.json()["api_response"]
            # handle case of 200 OK for not found.
            if not api_response:
                result["error"] = "Not Found"
            else:
                if isinstance(api_response, dict):
                    api_response = [api_response]
                for data in api_response:
                    if user and Classification.is_accessible(user["classification"], data["classification"]):
                        result["items"].append(data)
        # noinspection PyBroadException
        except Exception as err:
            err_msg = f"{source.name}-proxy did not return a response in the expected format"
            err_id = log_error(err_msg, err)
            result["error"] = f"{err_msg}. Error ID: {err_id}"

    return result


@federated_lookup_api.route("/tags/", methods=["GET"])
@api_login(require_role=[ROLES.external_query])
def get_tag_names(**kwargs):
    """Return the supported tags of each external service.

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
    return make_api_response(filtered_tag_names(user))


@federated_lookup_api.route("/enrich/<tag_name>/<tag>/", methods=["GET"])
@api_login(require_role=[ROLES.external_query])
def enrich_tags(tag_name: str, tag: str, **kwargs):
    """Search other services for additional information to enrich AL.

    Variables:
    tag_name => Tag to look up in the external system.
    tag => Tag value to lookup. *Must be double URL encoded.*

    Arguments: (optional)
    classification  => Classification of the tag [Default: minimum configured classification]
    sources         => | separated list of data sources. If empty, all configured sources are used.
    max_timeout     => Maximum execution time for the call in seconds
    limit           => limit the amount of returned results counted per source


    Data Block:
    None

    API call examples:
    /api/v4/federated_lookup/enrich/url/http%3A%2F%2Fmalicious.domain%2Fbad/
    /api/v4/federated_lookup/enrich/url/http%3A%2F%2Fmalicious.domain%2Fbad/?sources=vt|malware_bazar

    Result example:
    {                           # Dictionary of data source queried
        "vt": {
            "error": null,          # Error message returned by data source
            "items": [              # list of results from the source
                {
                    "link": "https://www.virustotal.com/gui/url/<id>",   # link to results
                    "count": 1,                                          # number of hits from the search
                    "classification": "TLP:C",                           # classification of the search result
                    "confirmed": true,                                   # Is the maliciousness attribution confirmed
                    "description": "",                                   # Description of the findings
                    "malicious": false,                                  # Is the file found malicious or not
                    "enrichment": [                                      # Semi structured details about the tag
                        {
                            "group": "yara_hits",
                            "name": "https://github.com/my/yararules", "name_description": "source of rule",
                            "value": "Base64_encoded_url", "value_description": "detects presence of b64 encoded URIs",
                        }
                    ],
                },
                ...,
            ],
        },
        ...,
    }
    """
    # re-encode the tag after being decoded going through flask/wsgi route
    tag = ul.quote(tag, safe="")
    user = kwargs["user"]
    qp = parse_qp(request=request)
    query_sources = qp["query_sources"]

    # validate what sources the user is allowed to submit requests to.
    # this must first be checked against what systems the user is allowed to see
    # additional tag level checking is then done later to provide feedback to user
    available_sources = [
        x for x in getattr(config.ui, "external_sources", [])
        if Classification.is_accessible(user["classification"], x.classification)
    ]

    with APMAwareThreadPoolExecutor(min(len(available_sources) + 1, os.cpu_count() + 4)) as executor:
        # create searches for external sources
        future_searches = {
            executor.submit(
                query_external,
                query_type="details",
                user=user,
                source=source,
                tag_name=tag_name,
                tag=tag,
                tag_classification=qp["tag_classification"],
                limit=qp["limit"],
                timeout=qp["max_timeout"]
            ): source.name
            for source in available_sources
            if not query_sources or source.name in query_sources
        }

        # results = {src: {"error": str, "items": list}}
        try:
            results = {
                future_searches[future]: future.result()
                for future in concurrent.futures.as_completed(future_searches, timeout=qp["max_timeout"])
                if future.result() is not None
            }
        except concurrent.futures.TimeoutError:
            # TimeoutError is raised after set time, not after the task is finished.
            # This means tasks that have not completed are still running, they are not killed due to timeout.

            # save results for anything that has finished
            results = {}
            for f, name in future_searches.items():
                if f.done:
                    results[name] = f.result()

    return make_api_response(results)
