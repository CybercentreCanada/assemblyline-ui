from copy import copy
from typing import Any, Optional
from assemblyline.common.dict_utils import recursive_update
from assemblyline_ui.config import CLASSIFICATION, config, SERVICE_LIST, SUBMISSION_PROFILES, STORAGE
from assemblyline.odm.models.submission import DEFAULT_SRV_SEL, SubmissionParams
from assemblyline.odm.models.user_settings import UserSettings

# Get the list of fields relating to the models
USER_SETTINGS_FIELDS = list(UserSettings.fields().keys())
SUBMISSION_PARAM_FIELDS = list(SubmissionParams.fields().keys())

def get_default_submission_profiles(user_default_values={}, classification=CLASSIFICATION.UNRESTRICTED):
    out = {}
    for profile in SUBMISSION_PROFILES.values():
        if CLASSIFICATION.is_accessible(classification, profile.classification):
            user_default_profile = user_default_values.get(profile.name, {})

            params = copy(profile.params.as_primitives(strip_null=True))
            out[profile.name] = recursive_update(params, user_default_values.get(profile.name, {}))

            service_spec = []
            # If there are any editable service parameters that haven't been set, then assign their default values
            for service, editable_params in profile.editable_params.items():
                service_obj = STORAGE.get_service_with_delta(service, as_obj=False)
                if not service_obj:
                    continue
                param_object = {'name': service, "params": []}
                profile_service_spec =  user_default_profile.get('service_spec', {}).get(service, {})
                for param in service_obj['submission_params']:
                    if param['name'] not in editable_params:
                        # Service parameter isn't allowed to be overridden in this profile
                        continue

                    new_param = copy(param)
                    if profile_service_spec.get(param['name']):
                        # Overwrite with user-specific value for profile
                        new_param['value'] = profile_service_spec[param['name']]
                    new_param["hide"] = False
                    param_object["params"].append(new_param)
                service_spec.append(param_object)

            # Overwrite 'service_spec' value to be compliant with frontend rendering
            out[profile.name]['service_spec'] = service_spec
    return out

def get_default_service_spec(srv_list=None, user_default_values={}, classification=CLASSIFICATION.UNRESTRICTED):
    if not srv_list:
        srv_list = SERVICE_LIST

    out = []
    for x in srv_list:
        if x["submission_params"] and CLASSIFICATION.is_accessible(classification, x['classification']):
            param_object = {'name': x['name'], "params": []}
            for param in x.get('submission_params'):
                new_param = copy(param)
                new_param['value'] = user_default_values.get(x['name'], {}).get(param['name'], param['value'])
                param_object["params"].append(new_param)

            out.append(param_object)

    return out


def get_default_service_list(srv_list=None, default_selection=None, classification=CLASSIFICATION.UNRESTRICTED):
    if not default_selection:
        default_selection = DEFAULT_SRV_SEL
    if not srv_list:
        srv_list = SERVICE_LIST

    services = {}
    for item in srv_list:
        if not CLASSIFICATION.is_accessible(classification, item['classification']):
            continue
        grp = item['category']

        if grp not in services:
            services[grp] = []

        services[grp].append({"name": item["name"],
                              "category": grp,
                              "selected": (grp in default_selection or item['name'] in default_selection),
                              "is_external": item["is_external"],
                              "description": item["description"]})

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

    # Remove UI specific params that don't apply as submission params based on the model
    for param in USER_SETTINGS_FIELDS:
        if param not in SUBMISSION_PARAM_FIELDS:
            params.pop(param, None)

    return params
