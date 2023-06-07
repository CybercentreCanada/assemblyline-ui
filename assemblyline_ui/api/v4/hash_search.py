import concurrent.futures
import os
import re

from flask import request
from requests import Session, exceptions

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


class SkipDatasource(Exception):
    pass


def create_query_datasource(ds):
    def query_datasource(h, u):
        return {
            'error': None,
            'items': ds.parse(ds.query(h, **u), **u)
        }
    return query_datasource


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
        "items:
            [
                {
                    "confirmed": true,        # Is the maliciousness attribution confirmed or not
                    "data": {...}             # Raw data from the data source
                    "description": "",        # Description of the findings
                    "malicious": false,       # Is the file found malicious or not
                }
            ]
    }
    """
    result = {}
    if hash_type not in all_supported_tags.get(source.name, {}):
        return result

    session = Session()
    headers = {
        "accept": "application/json",
    }
    params = {
        "limit": limit,
        "max_timeout": timeout,
    }

    result = {"error": "", "items": []}

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
        result["error"] = "File hash not found."
    elif status_code != 200:
        # as we query across multiple sources, just log errors.
        err_msg = rsp.json()["api_error_message"]
        err_id = log_error(f"Error from {source.name}", err_msg, status_code)
        result["error"] = f"{err_msg}. Error ID: {err_id}"
    else:
        try:
            for data in rsp.json()["api_response"]:
                if user and Classification.is_accessible(user["classification"], data["classification"]):
                    result["items"].append(data)
        # noinspection PyBroadException
        except Exception as err:
            err_msg = f"{source.name}-proxy did not return a response in the expected format"
            err_id = log_error(err_msg, err)
            result["error"] = f"{err_msg}. Error ID: {err_id}"
    return result


# noinspection PyUnusedLocal
@hash_search_api.route("/external/<path:file_hash>/", methods=["GET"])
@api_login(require_role=[ROLES.external_query])
def search_external(file_hash: str, *args, **kwargs):
    """
    Search for a hash in multiple data sources as configured in the seed.

    Variables:
    file_hash   => Hash to search in the external data sources

    Arguments:(optional)
    sources          => | separated list of data sources
    classification   => Classification of the tag [Default: minimum configured classification]
    max_timeout     => Maximum execution time for the call in seconds [Default: 3 seconds]
    limit           => limit the amount of returned results counted per source [Default: 500]

    Data Block:
    None

    API call examples:
    /api/v4/hash_search/
    /api/v4/hash_search/123456...654321/?db=virustotal|al

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

    hash_type = next((x for x, y in HASH_MAP.items() if y.match(file_hash)), None)

    if not hash_type:
        return make_api_response("", f"Invalid hash. This API only supports {', '.join(HASH_MAP.keys())}.", 400)

    hash_classification = request.args.get("classification", Classification.UNRESTRICTED)

    # validate what sources the user is allowed to submit requests to.
    # this must first be checked against what systems the user is allowed to see
    # additional file hash level checking is then done later to provide feedback to user
    available_sources = [
        x for x in getattr(config.ui, "external_sources", [])
        if Classification.is_accessible(user["classification"], x.classification)
    ]

    with concurrent.futures.ThreadPoolExecutor(min(len(available_sources), os.cpu_count() + 4)) as executor:
        future_searches = {
            executor.submit(
                get_external_details,
                user=user,
                source=source,
                hash_type=hash_type,
                file_hash=file_hash,
                hash_classification=hash_classification,
                timeout=max(0, max_timeout - 0.5),
                limit=limit,
            ): source.name
            for source in available_sources
        }
        results = {
            future_searches[future]: future.result()
            for future in concurrent.futures.as_completed(future_searches, timeout=max_timeout)
        }

    status_code = 200
    error = ""
    if not results or all({"File hash not found." in s["error"] for s in results.values()}):
        status_code = 404
        error = "No results found."
    else:
        if any({s["error"] for s in results.values()}):
            status_code = 500
            error = "One or more errors occured. See individual source results for more details."

    return make_api_response(results, err=error, status_code=status_code)


# noinspection PyUnusedLocal
@hash_search_api.route("/<file_hash>/", methods=["GET"])
@api_login(require_role=[ROLES.alert_view, ROLES.submission_view])
def search_hash(file_hash, *args, **kwargs):
    """
    Search for a hash in multiple data sources as configured in the seed.

    Variables:
    file_hash   => Hash to search in the multiple data sources
                   [MD5, SHA1 or SHA256]

    Arguments:(optional)
    db          => | separated list of data sources
    max_timeout => Maximum execution time for the call in seconds

    Data Block:
    None

    API call examples:
    /api/v4/hash_search/
    /api/v4/hash_search/123456...654321/?db=nsrl|al

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
    if hash_type(file_hash) == "invalid":
        return make_api_response("", "Invalid hash. This API only supports MD5, SHA1 and SHA256.", 400)

    db_list = []
    invalid_sources = []
    db = request.args.get('db', None)
    if db:
        db_list = db.split("|")
        invalid_sources = []
        for x in db_list:
            if x not in sources:
                invalid_sources.append(x)

        for x in invalid_sources:
            db_list.remove(x)

    max_timeout = request.args.get('max_timeout', "2")
    # noinspection PyBroadException
    try:
        max_timeout = float(max_timeout)
    except Exception:
        max_timeout = 2.0

    if len(db_list) == 0 and len(invalid_sources) == 0:
        db_list = sources.keys()

    with concurrent.futures.ThreadPoolExecutor(len(db_list)) as executor:
        res = {db: executor.submit(sources[db], file_hash.lower(), user) for db in db_list}

    # TODO: Timeout part needs some love. Can't be done through dictionary comprehension.
    return make_api_response({k: v.result(timeout=max_timeout) for k, v in res.items()})


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
    return make_api_response(sorted(sources.keys()))
