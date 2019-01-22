
from flask import request
from riak import RiakError

from assemblyline.common import forge
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from assemblyline.datastore import SearchException
from assemblyline.odm.models.tc_signature import DRAFT_STATUSES, DEPLOYED_STATUSES

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'tc_signature'
tc_sigs_api = make_subapi_blueprint(SUB_API, api_version=4)
tc_sigs_api._doc = "Perform operations on tagcheck signatures"


def is_valid_status(data, user):
    status = data.pop('al_status', None)
    if status in DEPLOYED_STATUSES and not user.get('is_admin', False):
        return False
    return True


@tc_sigs_api.route("/<name>/", methods=["PUT"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False)
def add_signature(name, **kwargs):
    """
    Add a tagcheck signature to the system
       
    Variables:
    name     =>  Name of the signature (must be unique)
    
    Arguments: 
    None
    
    Data Block (REQUIRED):
    {                         # Tagcheck signature block
     "callback": None,          # Callback function when the signature fires
     "classification": None ,   # Classification of the signature
     "comment": "",             # Comments about the signature
     "implant_family": "",      # Implant family
     "score": 'HIGH',           # Score assigned to the signature
     "status": "DEPLOYED",      # Status of the signature (DEPLOYED, DISABLED)
     "threat_actor": "",        # Threat actor assigned to the signature
     "values": [""],            # Rule regexes
    }

    Result example:
    {"success": true}        # If saving the rule was a success or not
    """
    user = kwargs['user']
    data = request.json
    data['name'] = name

    if not Classification.is_accessible(user['classification'], data.get('classification',
                                                                         Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    if not is_valid_status(data, user):
        return make_api_response("", "Only admins are allowed to deploy or disable signatures", 403)

    if STORAGE.tc_signature.get(name):
        return make_api_response({"success": False}, "Signature name already exists", 400)
    else:
        return make_api_response({"success": STORAGE.tc_signature.save(name, data)})


# noinspection PyPep8Naming
@tc_sigs_api.route("/change_status/<name>/<status>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_status(name, status, **kwargs):
    """
    Change the status of a tagcheck signature
       
    Variables:
    name    =>  signature name
    status  =>  New state
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { "success" : true }      #If saving the rule was a success or not
    """
    # TODO: A user should not be able to change the signature status if it's already in a deployed state
    user = kwargs['user']

    if status not in DRAFT_STATUSES and status not in DEPLOYED_STATUSES:
        return make_api_response("", "Invalid status %s." % status, 400)

    if not user['is_admin'] and status in DEPLOYED_STATUSES:
        return make_api_response("", "Only admins are allowed to deploy or disable signatures", 403)

    sig = STORAGE.tc_signature.get(name)
    if not sig:
        return make_api_response("", f"Signature not found. ({name})", 404)
    else:
        if not Classification.is_accessible(user['classification'], sig.classification):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        sig.al_status = status
        return make_api_response({"success": STORAGE.tc_signature.save(name, sig)})


@tc_sigs_api.route("/<name>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_signature(name, **kwargs):
    """
    Get the detail of a tagcheck signature based of its name
    
    Variables:
    name    =>     Signature Name
    
    Arguments: 
    None
    
    Data Block:
    None
     
    Result example:
    {                         # Tagcheck signature block
     "callback": None,          # Callback function when the signature fires
     "classification": None ,   # Classification of the signature
     "comment": "",             # Comments about the signature
     "implant_family": "",      # Implant family
     "score": 'HIGH',           # Score assigned to the signature
     "status": "DEPLOYED",      # Status of the signature (DEPLOYED, DISABLED)
     "threat_actor": "",        # Threat actor assigned to the signature
     "values": [""],            # Rule regexes
    }
    """
    user = kwargs['user']
    sig = STORAGE.tc_signature.get(name, as_obj=False)
    if sig:
        if not Classification.is_accessible(user['classification'], sig['classification']):
            return make_api_response("", "Your are not allowed to view this signature.", 403)
        return make_api_response(sig)
    else:
        return make_api_response("", f"Signature not found. ({name})", 404)


@tc_sigs_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def list_signatures(**kwargs):
    """
    List all the tagcheck signatures in the system.
    
    Variables:
    None 
    
    Arguments: 
    offset       => Offset at which we start giving signatures
    query        => Query to apply on the signature list
    rows         => Numbers of signatures to return

    Data Block:
    None
    
    Result example:
    {"total": 201,                # Total signatures found
     "offset": 0,                 # Offset in the signature list
     "count": 100,                # Number of signatures returned
     "items": [{                  # List of Tagcheck signature blocks
       "name": "SIG_ID_NAME",        # Signature name
       "callback": None,             # Callback function when the signature fires
       "classification": None ,      # Classification of the signature
       "comment": "",                # Comments about the signature
       "implant_family": "",         # Implant family
       "score": 'HIGH',              # Score assigned to the signature
       "status": "DEPLOYED",         # Status of the signature (DEPLOYED, DISABLED)
       "threat_actor": "",           # Threat actor assigned to the signature
       "values": [""],               # Rule regexes
       }, ... ]
    }
    """
    user = kwargs['user']
    offset = int(request.args.get('offset', 0))
    length = int(request.args.get('rows', 100))
    query = request.args.get('query', f"{STORAGE.ds.ID}:*")

    try:
        return make_api_response(STORAGE.tc_signature.search(query, offset=offset, rows=length,
                                                             access_control=user['access_control'], as_obj=False))
    except RiakError as e:
        if e.value == "Query unsuccessful check the logs.":
            return make_api_response("", "The specified search query is not valid.", 400)
        else:
            raise
    except SearchException:
        return make_api_response("", "The specified search query is not valid.", 400)


# noinspection PyPep8Naming
@tc_sigs_api.route("/<name>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False, require_admin=True)
def remove_signature(name, **kwargs):
    """
    Delete a tagcheck signature from the system

    Variables:
    name    =>  signature name

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "success" : true }      #If deleting the rule was a success or not
    """
    user = kwargs['user']

    sig = STORAGE.tc_signature.get(name)
    if not sig:
        return make_api_response("", f"Signature does not exist. ({name})", 404)
    else:
        if not Classification.is_accessible(user['classification'], sig.classification):
            return make_api_response("", "You are not allowed to delete this signature", 403)

        return make_api_response({"success": STORAGE.tc_signature.delete(name)})


@tc_sigs_api.route("/<name>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def set_signature(name, **kwargs):
    """
    Update a signature defined by a name.
    
    Variables:
    name    =>     Name of the signature
    
    Arguments: 
    None
    
    Data Block (REQUIRED):
    {                         # Tagcheck signature block
     "callback": None,          # Callback function when the signature fires
     "classification": None ,   # Classification of the signature
     "comment": "",             # Comments about the signature
     "implant_family": "",      # Implant family
     "score": 'HIGH',           # Score assigned to the signature
     "status": "DEPLOYED",      # Status of the signature (DEPLOYED, DISABLED)
     "threat_actor": "",        # Threat actor assigned to the signature
     "values": [""],            # Rule regexes
    }
    
    Result example:
    {"success": true}      #If saving the rule was a success or not
    """
    # TODO: A user should not be able to change the signature status if it's already in a deployed state
    user = kwargs['user']
    data = request.json

    if 'name' in data and name != data['name']:
        return make_api_response({"success": False}, "You cannot change the tagcheck signature name", 400)

    if not is_valid_status(data, user):
        return make_api_response("", "Only admins are allowed to deploy or disable signatures", 403)

    if not Classification.is_accessible(user['classification'], data.get('classification',
                                                                         Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    sig = STORAGE.tc_signature.get(name, as_obj=False)
    if sig:
        sig.update(data)
        return make_api_response({"success": STORAGE.tc_signature.save(name, sig)})
    else:
        return make_api_response({"success": False}, "Signature does not exist", 404)
