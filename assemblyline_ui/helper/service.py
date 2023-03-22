from copy import copy
from typing import Any, Optional
from assemblyline_ui.config import config, SERVICE_LIST
from assemblyline.odm.models.submission import DEFAULT_SRV_SEL


def get_default_service_spec(srv_list=None, user_default_values={}):
    if not srv_list:
        srv_list = SERVICE_LIST

    out = []
    for x in srv_list:
        if x["submission_params"]:
            param_object = {'name': x['name'], "params": []}
            for param in x.get('submission_params'):
                new_param = copy(param)
                new_param['value'] = user_default_values.get(x['name'], {}).get(param['name'], param['value'])
                param_object["params"].append(new_param)

            out.append(param_object)

    return out


def get_default_service_list(srv_list=None, default_selection=None):
    if not default_selection:
        default_selection = DEFAULT_SRV_SEL
    if not srv_list:
        srv_list = SERVICE_LIST

    services = {}
    for item in srv_list:
        grp = item['category']

        if grp not in services:
            services[grp] = []

        services[grp].append({"name": item["name"],
                              "category": grp,
                              "selected": (grp in default_selection or item['name'] in default_selection),
                              "is_external": item["is_external"]})

    return [{"name": k, "selected": k in default_selection, "services": v} for k, v in services.items()]


def simplify_services(services):
    out = []
    for item in services:
        if item["selected"]:
            out.append(item["name"])
        else:
            for srv in item["services"]:
                if srv["selected"]:
                    out.append(srv["name"])

    return out


def simplify_service_spec(service_spec):
    params = {}
    for spec in service_spec:
        service = spec['name']
        for param in spec['params']:
            if param['value'] != param['default']:
                params[service] = params.get(service, {})
                params[service][param['name']] = param['value']

    return params


def ui_to_submission_params(params) -> Optional[dict[str, Any]]:
    if params is None:
        return params

    # Simplify services params
    if "service_spec" in params:
        params["service_spec"] = simplify_service_spec(params["service_spec"])
    else:
        params['service_spec'] = {}

    # Simplify service selection
    if "services" in params and isinstance(params['services'], list):
        params['services'] = {'selected': simplify_services(params["services"])}

    params['ttl'] = int(params.get('ttl', config.submission.dtl))

    # Remove UI specific params
    params.pop('default_zip_password', None)
    params.pop('download_encoding', None)
    params.pop('expand_min_score', None)
    params.pop('submission_view', None)
    params.pop('ui4', None)
    params.pop('ui4_ask', None)

    return params
