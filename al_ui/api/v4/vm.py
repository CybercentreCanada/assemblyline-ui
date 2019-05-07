
from flask import request

from al_ui.api.base import api_login, make_api_response, make_subapi_blueprint
from al_ui.config import STORAGE
from assemblyline.datastore import SearchException

SUB_API = 'vm'
vm_api = make_subapi_blueprint(SUB_API, api_version=4)
vm_api._doc = "Manage the different Virtual machines of the system"


@vm_api.route("/<vm>/", methods=["PUT"])
@api_login(require_admin=True, allow_readonly=False)
def add_virtual_machine(vm, **_):
    """
    Add the vm configuration to the system
    
    Variables: 
    vm       => Name of the vm
    
    Arguments:
    None
    
    Data Block:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of service workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds interval
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }
    
    Result example:
    { "success" : True }
    """
    data = request.json
    
    if not STORAGE.vm.get(vm):
        if STORAGE.service_delta.get(vm):
            return make_api_response({"success": STORAGE.vm.save(vm, data)})
        else:
            return make_api_response({"success": False}, "You cannot add a vm which as no matching service name", 400)
    else:
        return make_api_response({"success": False}, "You cannot add a vm that already exists...", 400)


@vm_api.route("/<vm>/", methods=["GET"])
@api_login(require_admin=True, audit=False, allow_readonly=False)
def get_virtual_machine(vm, **_):
    """
    Load the configuration for a given virtual machine
    
    Variables: 
    vm       => Name of the virtual machine to get the info
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds interval
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }                
    """
    vm_data = STORAGE.vm.get(vm, as_obj=False)
    if vm_data:
        return make_api_response(vm_data)
    else:
        return make_api_response("", err=f"{vm} virtual machine does not exist", status_code=404)


@vm_api.route("/list/", methods=["GET"])
@api_login(require_admin=True, audit=False, allow_readonly=False)
def list_virtual_machine(**_):
    """
    List all virtual machines of the system.
    
    Variables:
    offset       => Offset at which we start giving virtual machines
    query        => Query to apply on the virtual machines list
    rows         => Numbers of virtual machines to return
    
    Arguments: 
    None
    
    Data Block:
    None
    
    Result example:
    [   {
         enabled: true,                  # Is VM enabled
         name: "Extract",                # Name of the VM
         num-workers: 1,                 # Number of service workers in that VM
         os_type: "windows",             # Type of OS
         os_variant: "win7",             # Variant of OS
         ram: 1024,                      # Amount of RAM
         revert_every: 600,              # Auto revert seconds interval
         vcpus: 1,                       # Number of CPUs
         virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
        },
    ...]
    """
    offset = int(request.args.get('offset', 0))
    rows = int(request.args.get('rows', 100))
    query = request.args.get('query', "id:*")

    try:
        return make_api_response(STORAGE.vm.search(query, offset=offset, rows=rows, as_obj=False))
    except SearchException as e:
        return make_api_response("", f"SearchException: {e}", 400)


@vm_api.route("/<vm>/", methods=["DELETE"])
@api_login(require_admin=True, allow_readonly=False)
def remove_virtual_machine(vm, **_):
    """
    Remove the vm configuration
    
    Variables: 
    vm       => Name of the vm
    
    Arguments:
    None
    
    Data Block:
    None
    
    Result example:
    {"success": True}    # Was is a success 
    """
    vm_data = STORAGE.vm.get(vm)
    if vm_data:
        return make_api_response({"success": STORAGE.vm.delete(vm)})
    else:
        return make_api_response({"success": False},
                                 err=f"VM {vm} does not exist",
                                 status_code=404)


@vm_api.route("/<vm>/", methods=["POST"])
@api_login(require_admin=True, allow_readonly=False)
def set_virtual_machine(vm, **_):
    """
    Save the configuration of a given virtual machine
    
    Variables: 
    vm    => Name of the virtual machine
    
    Arguments: 
    None
    
    Data Block:
    { 
     enabled: true,                  # Is VM enabled
     name: "Extract",                # Name of the VM
     num_workers: 1,                 # Number of workers
     os_type: "windows",             # Type of OS
     os_variant: "win7",             # Variant of OS
     ram: 1024,                      # Amount of RAM
     revert_every: 600,              # Auto revert seconds intervale
     vcpus: 1,                       # Number of CPUs
     virtual_disk_url: "img.qcow2"   # Name of the virtual disk to download
    }
    
    Result example:
    {"success": true }    #Saving the virtual machine info succeded
    """
    data = request.json
    current_vm = STORAGE.vm.get(vm, as_obj=False)

    if not current_vm:
        return make_api_response({"success": False}, "The virtual machine you are trying to modify does not exist", 404)

    if 'name' in data and vm != data['name']:
        return make_api_response({"success": False}, "You cannot change the virtual machine name", 400)

    current_vm.update(data)

    return make_api_response({"success": STORAGE.vm.save(vm, current_vm)})
