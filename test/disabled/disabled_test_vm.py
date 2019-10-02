import json
import pytest
import random

from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.vm import VM
from assemblyline.odm.randomizer import random_model_obj, SERVICES
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services


NUM_VMS = 10
ds = forge.get_datastore()
vm_list = []


def purge_vm():
    wipe_users(ds)
    wipe_services(ds)
    ds.vm.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_services(ds)

    for x in range(NUM_VMS):
        vm = random_model_obj(VM)
        vm.name = random.choice(list(SERVICES.keys()))
        SERVICES.pop(vm.name)
        vm_list.append(vm.name)
        ds.vm.save(vm.name, vm)

    ds.vm.commit()

    request.addfinalizer(purge_vm)
    return ds


# noinspection PyUnusedLocal
def test_add_virtual_machine(datastore, login_session):
    _, session = login_session

    vm = random_model_obj(VM).as_primitives()
    vm['name'] = random.choice(list(SERVICES.keys()))
    SERVICES.pop(vm['name'])
    vm_list.append(vm['name'])

    resp = get_api_data(session, f"{HOST}/api/v4/vm/{vm['name']}/", method="PUT", data=json.dumps(vm))
    assert resp['success']

    ds.vm.commit()

    new_vm = ds.vm.get(vm['name'], as_obj=False)
    assert new_vm == vm


# noinspection PyUnusedLocal
def test_get_virtual_machine(datastore, login_session):
    _, session = login_session

    vm_name = random.choice(vm_list)

    resp = get_api_data(session, f"{HOST}/api/v4/vm/{vm_name}/")
    assert resp == ds.vm.get(vm_name, as_obj=False)


# noinspection PyUnusedLocal
def test_list_virtual_machines(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/vm/list/")
    assert resp['total'] == len(vm_list)
    for vm in resp['items']:
        assert vm['name'] in vm_list


# noinspection PyUnusedLocal
def test_remove_virtual_machine(datastore, login_session):
    _, session = login_session

    vm_name = random.choice(vm_list)
    resp = get_api_data(session, f"{HOST}/api/v4/vm/{vm_name}/", method="DELETE")
    assert resp['success']

    vm_list.remove(vm_name)
    ds.vm.commit()

    assert ds.vm.get(vm_name) is None


# noinspection PyUnusedLocal
def test_set_virtual_machine(datastore, login_session):
    _, session = login_session

    vm_name = random.choice(vm_list)
    vm_data = ds.vm.get(vm_name, as_obj=False)
    vm_data['num_workers'] = 111
    vm_data['ram'] = 111
    vm_data['vcpus'] = 111

    resp = get_api_data(session, f"{HOST}/api/v4/vm/{vm_name}/", method="POST", data=json.dumps(vm_data))
    assert resp['success']

    ds.vm.commit()
    assert vm_data == ds.vm.get(vm_name, as_obj=False)
