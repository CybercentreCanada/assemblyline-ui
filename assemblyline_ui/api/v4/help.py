
import re

from assemblyline.common import forge
from assemblyline_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from assemblyline_ui.config import STORAGE, CLASSIFICATION
from assemblyline.common.constants import DEFAULT_SERVICE_ACCEPTS, DEFAULT_SERVICE_REJECTS
from assemblyline.odm.models.tagging import Tagging

SUB_API = 'help'
constants = forge.get_constants()
config = forge.get_config()
classification_definition = CLASSIFICATION.get_parsed_classification_definition()

help_api = make_subapi_blueprint(SUB_API, api_version=4)
help_api._doc = "Provide information about the system configuration"


@help_api.route("/classification_definition/")
@api_login(audit=False, check_xsrf_token=False)
def get_classification_definition(**_):
    """
    Return the current system classification definition

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    A parsed classification definition. (This is more for internal use)
    """
    return make_api_response(classification_definition)


# noinspection PyUnresolvedReferences
@help_api.route("/configuration/")
@api_login(audit=False, allow_readonly=False)
def get_system_configuration(**_):
    """
    Return the current system configuration:
        * Max file size
        * Max number of embedded files
        * Extraction's max depth
        * and many others...

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "<CONFIGURATION_ITEM>": <CONFIGURATION_VALUE>
    }
    """
    def get_config_item(parent, cur_item):
        if "." in cur_item:
            key, remainder = cur_item.split(".", 1)
            return get_config_item(parent.get(key, {}), remainder)
        else:
            return parent.get(cur_item, None)

    cat_map = {}
    stg_map = {}

    for srv in STORAGE.list_all_services(as_obj=False):
        name = srv.get('name', None)
        cat = srv.get('category', None)
        if cat and name:
            temp_cat = cat_map.get(cat, [])
            temp_cat.append(name)
            cat_map[cat] = temp_cat

        stg = srv.get('stage', None)
        if stg and name:
            temp_stg = stg_map.get(stg, [])
            temp_stg.append(name)
            stg_map[stg] = temp_stg

    shareable_config_items = [
        "core.ingester.default_max_extracted",
        "core.ingester.default_max_supplementary",
        "services.categories",
        "services.min_service_workers",
        "services.preferred_update_channel",
        "services.stages",
        "submission.default_max_extracted",
        "submission.default_max_supplementary",
        "submission.dtl",
        "submission.max_dtl",
        "submission.max_extraction_depth",
        "submission.max_file_size",
        "submission.max_metadata_length",
        "submission.tag_types.attribution",
        "submission.tag_types.behavior",
        "submission.tag_types.ioc",
        "ui.allow_raw_downloads",
        "ui.audit",
        "ui.download_encoding",
        "ui.enforce_quota",
        "ui.ingest_max_priority"
    ]

    out = {}
    config_dict = config.as_primitives()
    for item in shareable_config_items:
        out[item] = get_config_item(config_dict, item)

    out["services.categories"] = [[x, cat_map.get(x, [])] for x in out.get("services.categories", None)]
    out["services.stages"] = [[x, stg_map.get(x, [])] for x in out.get("services.stages", None)]

    return make_api_response(out)


@help_api.route("/constants/")
@api_login(audit=False, allow_readonly=False)
def get_systems_constants(**_):
    """
    Return the current system configuration constants which includes:
        * Priorities
        * File types
        * Service tag types
        * Service tag contexts

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    {
        "priorities": {},
        "file_types": [],
        "tag_types": [],
        "tag_contexts": []
    }
    """
    accepts_map = {}
    rejects_map = {}
    default_list = []

    for srv in STORAGE.list_all_services(as_obj=False):
        name = srv.get('name', None)
        if name:
            accept = srv.get('accepts', DEFAULT_SERVICE_ACCEPTS)
            reject = srv.get('rejects', DEFAULT_SERVICE_REJECTS)
            if accept == DEFAULT_SERVICE_ACCEPTS and reject == DEFAULT_SERVICE_REJECTS:
                default_list.append(name)
            else:
                accepts_map[name] = re.compile(accept)
                rejects_map[name] = re.compile(reject)

    out = {
        "max_priority": constants.MAX_PRIORITY,
        "priorities": constants.PRIORITIES,
        "file_types": [[t,
                        sorted([x for x in accepts_map.keys()
                                if re.match(accepts_map[x], t) and not re.match(rejects_map[x], t)])]
                       for t in sorted(constants.RECOGNIZED_TYPES.keys())],
        "tag_types": sorted(list(Tagging.flat_fields().keys()))
    }
    out['file_types'].insert(0, ["*", default_list])

    return make_api_response(out)


@help_api.route("/tos/")
@api_login(audit=False, check_xsrf_token=False)
def get_terms_of_service(**_):
    """
    Return the current system terms of service

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
    Terms of service as markdown format
    """
    return make_api_response(config.ui.tos)
