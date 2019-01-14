from copy import deepcopy
from operator import itemgetter

from flask import request

from assemblyline.common import forge
from al_ui.api.base import api_login, make_api_response
from al_ui.api.v3 import core
from al_ui.config import STORAGE

SUB_API = 'tc_signature'

Classification = forge.get_classification()

config = forge.get_config()

tc_sigs_api = core.make_subapi_blueprint(SUB_API)
tc_sigs_api._doc = "Perform operations on tagcheck signatures"


TC_SIG_DEFAULT = {
    "callback": "",
    "classification": "U",
    "comment": "",
    "implant_family": "",
    "score": "HIGH",
    "status": "DEPLOYED",
    "threat_actor": "",
    "values": [""]
}
TC_SIG_ALLOWED_NULL = ['callback', 'classification', 'comment', 'implant_family', 'threat_actor']


class InvalidSignatureError(Exception):
    pass


# noinspection PyBroadException
def validate_signature(data):
    try:
        _validate_signature(data)
    except Exception:
        return False
    return True


def _validate_signature(data):
    if not isinstance(data, dict):
        raise InvalidSignatureError("Not a dictionary object")

    for key, value in data.items():
        if key not in TC_SIG_DEFAULT:
            raise InvalidSignatureError("Invalid key [%s]" % key)
        else:
            if not isinstance(value, type(TC_SIG_DEFAULT[key])) \
                    and not (isinstance(value, str) and isinstance(TC_SIG_DEFAULT[key], str)):
                if value is None:
                    if key not in TC_SIG_ALLOWED_NULL:
                        raise InvalidSignatureError("Key '%s' not allowed to be None" % key)
                else:
                    raise InvalidSignatureError("Invalid value for key [%s]" % key)

    for key in TC_SIG_DEFAULT.keys():
        if key not in data:
            raise InvalidSignatureError("Missing key [%s]" % key)


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
    
    if not Classification.is_accessible(user['classification'], data.get('classification',
                                                                         Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    sigs = STORAGE.get_blob('tagcheck_signatures')
    
    if not sigs:
        sigs = {}

    if name in sigs:
        return make_api_response({"success": False}, "Signature name already exists", 400)
    else:
        if validate_signature(data):
            sigs[name] = data
            STORAGE.save_blob('tagcheck_signatures', sigs)
        else:
            return make_api_response({"success": False}, "Invalid signature data", 400)
    return make_api_response({"success": True})


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
    DEPLOYED_STATUSES = ['DEPLOYED', 'DISABLED']
    DRAFT_STATUSES = ['STAGING', 'TESTING']

    user = kwargs['user']

    if status not in DRAFT_STATUSES and status not in DEPLOYED_STATUSES:
        return make_api_response("", "Invalid status %s." % status, 400)

    if not user['is_admin'] and status in DEPLOYED_STATUSES:
        return make_api_response("",
                                 "Only admins are allowed to change the signature status to a deployed status.",
                                 403)

    sigs = STORAGE.get_blob('tagcheck_signatures')
    if not sigs or name not in sigs:
        return make_api_response("", "Signature not found. (%s)" % name, 404)
    else:
        if not Classification.is_accessible(user['classification'], sigs[name].get('classification',
                                                                                   Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed change status on this signature", 403)
    
        sigs[name]['status'] = status
        STORAGE.save_blob('tagcheck_signatures', sigs)
        return make_api_response({"success": True})


# noinspection PyPep8Naming
@tc_sigs_api.route("/<name>/", methods=["DELETE"])
@api_login(required_priv=['W'], allow_readonly=False, require_admin=True)
def delete(name, **kwargs):
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

    sigs = STORAGE.get_blob('tagcheck_signatures')
    if not sigs or name not in sigs:
        return make_api_response("", "Signature does not exist. (%s)" % name, 404)
    else:
        if not Classification.is_accessible(user['classification'], sigs[name].get('classification',
                                                                                   Classification.UNRESTRICTED)):
            return make_api_response("", "You are not allowed to delete this signature", 403)

        del sigs[name]
        STORAGE.save_blob('tagcheck_signatures', sigs)
        return make_api_response({"success": True})


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
    sigs = STORAGE.get_blob('tagcheck_signatures')
    if sigs and name in sigs:
        if sigs[name]['classification'] == "None":
            sigs[name]['classification'] = Classification.UNRESTRICTED
        if not Classification.is_accessible(user['classification'],
                                            sigs[name].get('classification', Classification.UNRESTRICTED)):
            return make_api_response("", "Your are not allowed to view this signature.", 403)
        return make_api_response(sigs[name])
    else:
        return make_api_response("", "Signature not found. (%s)" % name, 404)


@tc_sigs_api.route("/list/", methods=["GET"])
@api_login(required_priv=['R'], allow_readonly=False)
def list_signatures(**kwargs):
    """
    List all the tagcheck signatures in the system.
    
    Variables:
    None 
    
    Arguments: 
    offset       => Offset at which we start giving signatures
    length       => Numbers of signatures to return
    filter       => Filter to apply on the signature list
    
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
    length = int(request.args.get('length', 100))
    query = request.args.get('filter', "*").lower()

    output = {"total": 0, "offset": offset, "count": length, "items": []}
    sigs = STORAGE.get_blob('tagcheck_signatures')

    if not sigs:
        return make_api_response(output)

    if query == "*":
        items = []
        for sig_name in sorted(sigs.keys()):
            sig_val = sigs[sig_name]
            if sig_val['classification'] == "None":
                sig_val['classification'] = Classification.UNRESTRICTED
            if user and Classification.is_accessible(user['classification'], sig_val['classification']):
                cur_item = deepcopy(sig_val)
                cur_item['name'] = sig_name
                items.append(cur_item)
        output['items'] = sorted(items[offset:offset + length], key=itemgetter('name'))
        output['total'] = len(items)
    elif query:
        filtered = []
        for sig_name in sorted(sigs.keys()):
            sig_val = sigs[sig_name]
            if sig_val['classification'] == "None":
                sig_val['classification'] = Classification.UNRESTRICTED
            for cur_key, cur_val in sig_val.iteritems():
                temp_val = str(cur_val)
                if query in temp_val.lower() and user \
                        and Classification.is_accessible(user['classification'], sig_val['classification']):
                    cur_item = deepcopy(sig_val)
                    cur_item['name'] = sig_name
                    filtered.append(cur_item)
                    break

        output["items"] = sorted(filtered[offset:offset + length], key=itemgetter('name'))
        output["total"] = len(filtered)

    return make_api_response(output)


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
    user = kwargs['user']
    data = request.json

    if not Classification.is_accessible(user['classification'], data.get('classification',
                                                                         Classification.UNRESTRICTED)):
        return make_api_response("", "You are not allowed to add a signature with "
                                     "higher classification than yours", 403)

    sigs = STORAGE.get_blob('tagcheck_signatures')
    if sigs and name in sigs:
        if validate_signature(data):
            sigs[name] = data
            STORAGE.save_blob('tagcheck_signatures', sigs)
        else:
            return make_api_response({"success": False}, "Invalid signature data", 400)
    else:
        return make_api_response({"success": False}, "Signature does not exist", 404)

    return make_api_response({"success": True})
