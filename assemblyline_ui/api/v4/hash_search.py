import concurrent.futures
import os
import re

from flask import request
from requests import Session

from assemblyline.common.importing import load_module_by_path
from assemblyline.odm.models.user import ROLES
from assemblyline.odm import base
from assemblyline.datasource.common import hash_type
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.api.v4.federated_lookup import all_supported_tags, log_error
from assemblyline_ui.config import LOGGER, config, CLASSIFICATION as Classification

SUB_API = 'hash_search'
hash_search_api = make_subapi_blueprint(SUB_API, api_version=4)
hash_search_api._doc = "Search hashes through multiple data sources"

HASH_MAP = {
    "sha256": re.compile(base.SHA256_REGEX),
    "md5": re.compile(base.MD5_REGEX),
    "sha1": re.compile(base.SHA1_REGEX),
    "ssdeep": re.compile(base.SSDEEP_REGEX),
    "tlsh": re.compile(base.TLSH_REGEX),
}

HNF = "File hash not found."
NOT_SUPPORTED = "Unsupported hash type."


class SkipDatasource(Exception):
    pass


def create_query_datasource(ds):
    def query_datasource(h, u):
        return {
            'error': None,
            'items': ds.parse(ds.query(h, **u), **u)
        }
    return query_datasource


external_sources = getattr(config.ui, "external_sources", [])
sources = {}
# noinspection PyBroadException
try:
    for name, settings in config.datasources.items():
        name = name.lower()
        classpath = 'unknown'
        # noinspection PyBroadException
        try:
            classpath = settings.classpath
            cfg = settings.config
            if isinstance(cfg, str):
                # TODO: this needs testing that can only be done when a service datasource is available.
                path = cfg
                cfg = config
                for point in path.split('.'):
                    if 'enabled' in cfg:
                        if not cfg['enabled']:
                            raise SkipDatasource()
                    cfg = cfg.get(point)
            cls = load_module_by_path(classpath)
            obj = cls(LOGGER, **cfg)
            sources[name] = create_query_datasource(obj)
        except SkipDatasource:
            continue
        except Exception:
            LOGGER.exception(
                "Problem creating %s datasource (%s)", name, classpath
            )
except Exception:
    LOGGER.exception("No datasources")


def get_external_details(
    user,
    source,
    file_hash: str,
    hash_type: str,
    hash_classification: str,
    limit: int,
    timeout: float,
):
    """Return the details from the external source.

    {
        "error": "",
        "items":
            [
                {
                    "confirmed": true,        # Is the maliciousness attribution confirmed or not
                    "data": {...},            # Raw data from the data source
                    "description": "",        # Description of the findings
                    "malicious": false,       # Is the file found malicious or not
                }
            ]
    }
    """
    sname = f"x.{source.name}"
    result = {"error": None, "items": []}
    if hash_type not in all_supported_tags.get(source.name, {}):
        result["error"] = NOT_SUPPORTED
        return result
    # check the query against the max supported classification of the hash type in the external system
    hash_type_classif = all_supported_tags[source.name][hash_type]
    if not Classification.is_accessible(user["classification"], hash_type_classif):
        result["error"] = NOT_SUPPORTED
        return result

    session = Session()
    headers = {
        "accept": "application/json",
    }
    params = {
        "limit": limit,
        "max_timeout": timeout,
    }

    # check query against the max supported classification of the external system
    # if this is not supported, we should let the user know.
    if not Classification.is_accessible(source.max_classification or Classification.UNRESTRICTED, hash_classification):
        result["error"] = "File hash classification exceeds max classification."
        return result

    # perform the lookup, ensuring access controls are applied
    url = f"{source.url}/details/{hash_type}/{file_hash}"
    rsp = session.get(url, params=params, headers=headers)

    status_code = rsp.status_code
    if status_code == 404 or status_code == 422:
        # continue searching configured sources if not found or invliad tag.
        result["error"] = HNF
    elif status_code != 200:
        # as we query across multiple sources, just log errors.
        err_msg = rsp.json()["api_error_message"]
        err_id = log_error(f"Error from {sname}", err_msg, status_code)
        result["error"] = f"{err_msg}. Error ID: {err_id}"
    else:
        try:
            for data in rsp.json()["api_response"]:
                if user and Classification.is_accessible(user["classification"], data["classification"]):
                    result["items"].append(data)
        # noinspection PyBroadException
        except Exception as err:
            err_msg = f"{sname}-proxy did not return a response in the expected format"
            err_id = log_error(err_msg, err)
            result["error"] = f"{err_msg}. Error ID: {err_id}"
    return result


# noinspection PyUnusedLocal
@hash_search_api.route("/<file_hash>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view, ROLES.external_query])
def search_hash(file_hash, *args, **kwargs):
    """
    Search for a hash in multiple data sources as configured in the seed.

    Variables:
    file_hash   => Hash to search in the multiple data sources
                   [MD5, SHA1, SHA256, SSDEEP, TLSH]

    Arguments:(optional)
    db               => | separated list of data sources, external sources are prefixed with `x.`
    classification   => Classification of the tag [Default: Submitter's maximum allowed classification]
    max_timeout      => Maximum execution time for the call in seconds [Default: 3]
    limit            => limit the amount of returned results counted per source [Default: 500]

    Data Block:
    None

    API call examples:
    /api/v4/hash_search/
    /api/v4/hash_search/123456...654321/?db=nsrl|al
    /api/v4/hash_search/123456...654321/?db=nsrl|al|x.virustotal

    Result example:
    {                           # Dictionary of:
        "al": {                   # Data source queried
          "error": null,            # Error message returned by data source
          "items": [                # List of items found in the data source
           {"confirmed": true,        # Is the maliciousness attribution confirmed or not
            "data": {...}             # Raw data from the data source
            "description": "",        # Description of the findings
            "malicious": false},      # Is the file found malicious or not
          ...
          ]
        },
        ...
    }
    """
    user = kwargs['user']
    submitted_hash_type = next((x for x, y in HASH_MAP.items() if y.match(file_hash)), None)
    if not submitted_hash_type:
        return make_api_response("", f"Invalid hash. This API only supports {', '.join(HASH_MAP.keys())}.", 400)

    # default to the submitters classification to prevent accidental data leak by forgetting to set a classification
    # but also allowing classification to be optional for when classification engine is disabled.
    hash_classification = request.args.get("classification", user["classification"])
    limit = request.args.get("limit", "500")
    max_timeout = request.args.get('max_timeout', "3")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 3.0

    db_list = []
    ext_list = []
    db = request.args.get('db', None)
    if db:
        for s in db.split("|"):
            if s.startswith("x."):
                ext_list.append(s)
            elif hash_type(file_hash) != "invalid" and s in sources:
                # internal db queries only support subset of hashes
                db_list.append(s)
    else:
        db_list = sources.keys()
        ext_list = [f"x.{s.name}" for s in external_sources]

    # validate what sources the user is allowed to submit requests to.
    # this must first be checked against what systems the user is allowed to see
    # additional file hash level checking is then done later to provide feedback to user
    ext = [
        s for s in external_sources
        if f"x.{s.name}" in ext_list and Classification.is_accessible(user["classification"], s.classification)
    ]

    total_sources = len(ext) + len(db_list)
    with concurrent.futures.ThreadPoolExecutor(min(total_sources + 1, os.cpu_count() + 4)) as executor:
        # create searches for external sources
        future_searches = {
            executor.submit(
                get_external_details,
                user=user,
                source=source,
                hash_type=submitted_hash_type,
                file_hash=file_hash,
                hash_classification=hash_classification,
                timeout=max(0, max_timeout - 0.5),
                limit=limit,
            ): f"x.{source.name}"
            for source in ext
        }

        # create searches for internal sources
        future_searches.update({
            executor.submit(sources[db], file_hash.lower(), user): db for db in db_list
        })

        results = {
            future_searches[future]: future.result()
            for future in concurrent.futures.as_completed(future_searches, timeout=max_timeout)
        }

    status_code = 200
    error = None
    # if any successful results at all are given we should return a success 200.
    # otherwise, if ALL results are 404s we should return a 404,
    # else fallback to return a generic server error
    res = results.values()
    if results and any({len(s.get("items", [])) for s in res}):
        # remove error message for Hash Not Found
        for r in res:
            if r["error"] == HNF:
                r["error"] = None
    elif not results or all({s["error"] == HNF for s in res}):
        status_code = 404
        error = HNF
    elif not results or all({s["error"] == NOT_SUPPORTED for s in res}):
        status_code = 422
        error = NOT_SUPPORTED
    else:
        if any({s["error"] for s in res}):
            status_code = 500
            error = "One or more errors occured. See individual source results for more details."

    return make_api_response(results, err=error, status_code=status_code)


# noinspection PyUnusedLocal
@hash_search_api.route("/list_data_sources/", methods=["GET"])
@api_login(audit=False, require_role=[ROLES.alert_view, ROLES.submission_view])
def list_data_sources(*args, **kwargs):
    """
    List all available data sources to use the hash_search API

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    [ <list of sources> ]
    """
    src = [f"x.{s.name}" for s in external_sources]
    src.extend(sources.keys())
    return make_api_response(sorted(src))
