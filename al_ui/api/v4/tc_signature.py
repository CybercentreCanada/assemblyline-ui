from flask import request

from assemblyline.common import forge
from assemblyline.common.isotime import iso_to_epoch
from assemblyline.datastore import SearchException
from assemblyline.odm.models.tc_signature import DRAFT_STATUSES, DEPLOYED_STATUSES
from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from al_ui.http_exceptions import AccessDeniedException

Classification = forge.get_classification()
config = forge.get_config()

SUB_API = 'tc_signature'
tc_sigs_api = make_subapi_blueprint(SUB_API, api_version=4)
tc_sigs_api._doc = "Perform operations on tagcheck signatures"


def test_status(data, user, sig=None):
    if sig is None:
        sig_status = None
    else:
        sig_status = sig.get('al_status', None)

    data_status = data.get('al_status', sig_status)

    if data_status != sig_status and not user.get('is_admin', False):
        if data_status in DEPLOYED_STATUSES:
            raise AccessDeniedException("Only admins are allowed to deploy or disable signatures")
        elif sig_status in DEPLOYED_STATUSES:
            raise AccessDeniedException("Only admins are allowed to change a signature already in "
                                        "deployed or disabled status")

def get_next_tc_id():
    res = STORAGE.tc_signature.search("id:*", fl="id", sort="id desc", rows=1, as_obj=False)
    if res['total'] > 0:
        return "TC_%06d" % (int(res['items'][0]['id'][3:]) + 1)
    else:
        return "TC_000001"

def get_signature_last_modified():
    res = STORAGE.tc_signature.search("id:*", fl="last_modified",
                                   sort="last_modified desc", rows=1, as_obj=False)
    if res['total'] > 0:
        return res['items'][0]['last_modified']
    return '1970-01-01T00:00:00.000000Z'


@tc_sigs_api.route("/", methods=["PUT"])
@api_login(audit=False, required_priv=['W'], allow_readonly=False)
def add_signature( **kwargs):
    """
    Add a tagcheck signature to the system
       
    Variables:
    None
    
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
    signature_id = get_next_tc_id()
    data['classification'] = data.get('classification', Classification.UNRESTRICTED) or Classification.UNRESTRICTED
    data.pop('last_modified', None)

    if not Classification.is_accessible(user['classification'], data['classification']):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    test_status(data, user)

    if STORAGE.tc_signature.search(f"name:{data['name']}", rows=0, as_obj=False)['total'] != 0:
        return make_api_response({"success": False}, "Signature name already exists", 400)
    else:
        try:
            return make_api_response({"success": STORAGE.tc_signature.save(signature_id, data), "tc_id": signature_id})
        except ValueError as e:
            return make_api_response({}, err=str(e), status_code=400)


# noinspection PyPep8Naming
@tc_sigs_api.route("/change_status/<tc_id>/<status>/", methods=["GET"])
@api_login(required_priv=['W'], allow_readonly=False)
def change_status(tc_id, status, **kwargs):
    """
    Change the status of a tagcheck signature
       
    Variables:
    tc_id   =>  ID of the signature
    status  =>  New state
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    { "success" : true }      #If saving the rule was a success or not
    """
    user = kwargs['user']

    if status not in DRAFT_STATUSES and status not in DEPLOYED_STATUSES:
        return make_api_response("", "Invalid status %s." % status, 400)

    sig = STORAGE.tc_signature.get(tc_id, as_obj=False)
    if not sig:
        return make_api_response("", f"Signature not found. ({tc_id})", 404)
    else:
        test_status({'al_status': status}, user, sig)

        if not Classification.is_accessible(user['classification'], sig['classification']):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        sig['al_status'] = status
        sig.pop('last_modified', None)
        return make_api_response({"success": STORAGE.tc_signature.save(tc_id, sig)})


@tc_sigs_api.route("/<tc_id>/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def get_signature(tc_id, **kwargs):
    """
    Get the detail of a tagcheck signature based of its name
    
    Variables:
    tc_id    =>     ID of the signature
    
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
    sig = STORAGE.tc_signature.get(tc_id, as_obj=False)
    if sig:
        if not Classification.is_accessible(user['classification'], sig['classification']):
            return make_api_response("", "Your are not allowed to view this signature.", 403)
        return make_api_response(sig)
    else:
        return make_api_response("", f"Signature not found. ({tc_id})", 404)


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
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*")

    try:
        return make_api_response(STORAGE.tc_signature.search(query, offset=offset, rows=rows,
                                                             access_control=user['access_control'], as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


# noinspection PyPep8Naming
@tc_sigs_api.route("/<tc_id>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False, require_admin=True)
def remove_signature(tc_id, **kwargs):
    """
    Delete a tagcheck signature from the system

    Variables:
    tc_id    =>  ID of the signature

    Arguments:
    None

    Data Block:
    None

    Result example:
    { "success" : true }      #If deleting the rule was a success or not
    """
    user = kwargs['user']

    sig = STORAGE.tc_signature.get(tc_id, as_obj=False)
    if not sig:
        return make_api_response("", f"Signature does not exist. ({tc_id})", 404)
    else:
        if not Classification.is_accessible(user['classification'], sig['classification']):
            return make_api_response("", "You are not allowed to delete this signature", 403)

        return make_api_response({"success": STORAGE.tc_signature.delete(tc_id)})


@tc_sigs_api.route("/<tc_id>/", methods=["POST"])
@api_login(required_priv=['W'], allow_readonly=False)
def set_signature(tc_id, **kwargs):
    """
    Update a signature defined by a name.
    
    Variables:
    tc_id    =>    ID of the signature

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
    user = kwargs['user']
    data = request.json

    if not Classification.is_accessible(user['classification'], data.get('classification',
                                                                         Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    sig = STORAGE.tc_signature.get(tc_id, as_obj=False)
    if sig:
        if 'name' in data and sig['name'] != data['name']:
            return make_api_response({"success": False}, "You cannot change the tagcheck signature name", 400)

        test_status(data, user, sig)
        sig.update(data)
        sig.pop('last_modified', None)
        try:
            return make_api_response({"success": STORAGE.tc_signature.save(tc_id, sig)})
        except ValueError as e:
            return make_api_response({}, err=str(e), status_code=400)
    else:
        return make_api_response({"success": False}, "Signature does not exist", 404)


@tc_sigs_api.route("/update_available/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def update_available(**_):
    """
    Check if updated signatures are.

    Variables:
    None

    Arguments:
    last_update        => Epoch time of last update.

    Data Block:
    None

    Result example:
    { "update_available" : true }      # If updated rules are available.
    """
    last_update = iso_to_epoch(request.args.get('last_update', '1970-01-01T00:00:00.000000Z'))
    last_modified = iso_to_epoch(get_signature_last_modified())

    return make_api_response({"update_available": last_modified > last_update})