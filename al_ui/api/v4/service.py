
from flask import request

from assemblyline.common import forge
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from assemblyline.common.dict_utils import get_recursive_delta

config = forge.get_config()

SUB_API = 'service'
service_api = make_subapi_blueprint(SUB_API, api_version=4)
service_api._doc = "Manage the different services"


@service_api.route("/constants/", methods=["GET"])
@api_login(audit=False, required_priv=['R'], allow_readonly=False)
def get_service_constants(**_):
    """
    Get global service constants.
    
    Variables: 
    None
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    {
        "categories": [
          "Antivirus", 
          "Extraction", 
          "Static Analysis", 
          "Dynamic Analysis"
        ], 
        "stages": [
          "FILTER", 
          "EXTRACT", 
          "SECONDARY", 
          "TEARDOWN"
        ]
    }
    """
    return make_api_response({
        'stages': config.services.stages,
        'categories': config.services.categories,
    })


@service_api.route("/versions/<servicename>/", methods=["GET"])
@api_login(require_admin=True, audit=False, allow_readonly=False)
def get_potential_versions(servicename, **_):
    """
    List the different versions of a service stored in the system

    Variables:
    servicename       => Name of the service to get the versions

    Arguments:
    None

    Data Block:
    None

    Result example:
    ['3.1.0', '3.2.0', '3.3.0', '4.0.0', ...]     # List of service versions
    """
    service = STORAGE.service_delta.get(servicename)
    if service:
        return make_api_response([item.version for item in
                                  STORAGE.service.search(f"id:{servicename}*", fl="version")['items']])
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/<servicename>/", methods=["GET"])
@api_login(require_admin=True, audit=False, allow_readonly=False)
def get_service(servicename, **_):
    """
    Load the configuration for a given service
    
    Variables: 
    servicename       => Name of the service to get the info
    
    Arguments:
    version           => Specific version of the service to get
    
    Data Block:
    None
    
    Result example:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extracts some stuff"
     'enabled': True,
     'install_by_default': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'supported_platforms': ['Linux'],
     'timeout': 60}
    """
    version = request.args.get('version', None)

    service = STORAGE.get_service_with_delta(servicename, version=version, as_obj=False)
    if service:
        return make_api_response(service)
    else:
        return make_api_response("", err=f"{servicename} service does not exist", status_code=404)


@service_api.route("/all/", methods=["GET"])
@api_login(audit=False, required_priv=['R'], allow_readonly=False)
def list_all_services(**_):
    """
    List all service configurations of the system.

    Variables:
    None

    Arguments:
    None

    Data Block:
    None

    Result example:
     [
        {'accepts': ".*"
         'category': 'Extraction',
         'classpath': 'al_services.alsvc_extract.Extract',
         'description': "Extracts some stuff",
         'enabled': True,
         'name': 'Extract',
         'rejects': 'empty'
         'stage': 'CORE'
         },
         ...
     ]
    """
    return make_api_response(STORAGE.list_all_services(full=True, as_obj=False))


@service_api.route("/<servicename>/", methods=["DELETE"])
@api_login(require_admin=True, allow_readonly=False)
def remove_service(servicename, **_):
    """
    Remove a service configuration
    
    Variables: 
    servicename       => Name of the service to remove
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": true}  # Has the deletion succeeded
    """
    svc = STORAGE.service_delta.get(servicename)

    if svc:
        success = True
        if not STORAGE.service_delta.delete(servicename):
            success = False
        if not STORAGE.service.delete_matching(f"id:{servicename}*"):
            success = False
        return make_api_response({"success": success})
    else:
        return make_api_response({"success": False},
                                 err=f"Service {servicename} does not exist",
                                 status_code=404)


@service_api.route("/<servicename>/", methods=["POST"])
@api_login(require_admin=True, allow_readonly=False)
def set_service(servicename, **_):
    """
    Calculate the delta between the original service config and
    the posted service config then saves that delta as the current
    service delta.
    
    Variables: 
    servicename    => Name of the service to save
    
    Arguments: 
    None
    
    Data Block:
    {'accepts': '(archive|executable|java|android)/.*',
     'category': 'Extraction',
     'classpath': 'al_services.alsvc_extract.Extract',
     'config': {'DEFAULT_PW_LIST': ['password', 'infected']},
     'cpu_cores': 0.1,
     'description': "Extract some stuff",
     'enabled': True,
     'install_by_default': True,
     'name': 'Extract',
     'ram_mb': 256,
     'rejects': 'empty|metadata/.*',
     'stage': 'EXTRACT',
     'submission_params': [{'default': u'',
       'name': 'password',
       'type': 'str',
       'value': u''},
      {'default': False,
       'name': 'extract_pe_sections',
       'type': 'bool',
       'value': False},
      {'default': False,
       'name': 'continue_after_extract',
       'type': 'bool',
       'value': False}],
     'supported_platforms': ['Linux'],
     'timeout': 60}
    
    Result example:
    {"success": true }    #Saving the user info succeded
    """
    data = request.json
    version = data.get('version', None)
    if not version:
        return make_api_response({"success": False}, "The service you are trying to modify does not exist", 404)

    current_service = STORAGE.service.get(f"{servicename}_{version}", as_obj=False)

    if not current_service:
        return make_api_response({"success": False}, "The service you are trying to modify does not exist", 404)

    if 'name' in data and servicename != data['name']:
        return make_api_response({"success": False}, "You cannot change the service name", 400)

    delta = get_recursive_delta(current_service, data)
    delta['version'] = version

    return make_api_response({"success": STORAGE.service_delta.save(servicename, delta)})
