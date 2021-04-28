
from assemblyline_ui.config import STORAGE, config
from assemblyline.odm.models.submission import DEFAULT_SRV_SEL


def get_default_service_spec(srv_list=None):
    if not srv_list:
        srv_list = STORAGE.list_all_services(as_obj=False, full=True)

    return [{"name": x['name'],
             "params": x["submission_params"]}
            for x in srv_list if x["submission_params"]]


def get_default_service_list(srv_list=None, default_selection=None):
    if not default_selection:
        default_selection = DEFAULT_SRV_SEL
    if not srv_list:
        srv_list = STORAGE.list_all_services(as_obj=False, full=True)

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


def ui_to_submission_params(params):
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
    params.pop('download_encoding', None)
    params.pop('expand_min_score', None)
    params.pop('submission_view', None)
    params.pop('ui4', None)
    params.pop('ui4_ask', None)

    return params
