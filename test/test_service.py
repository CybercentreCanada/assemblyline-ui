import json
import pytest
import random

from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.service import Service
from assemblyline.odm.randomizer import SERVICES
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services

config = forge.get_config()
ds = forge.get_datastore(config)


def purge_service():
    wipe_users(ds)
    wipe_services(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_services(ds)
    request.addfinalizer(purge_service)
    return ds



# noinspection PyUnusedLocal
def test_get_versions(datastore, login_session):
    _, session = login_session

    service = random.choice(list(SERVICES.keys()))
    resp = get_api_data(session, f"{HOST}/api/v4/service/versions/{service}/")
    assert resp == ['3.3.0', '4.0.0']


# noinspection PyUnusedLocal
def test_get_service(datastore, login_session):
    _, session = login_session

    service = random.choice(list(SERVICES.keys()))
    resp = get_api_data(session, f"{HOST}/api/v4/service/{service}/")
    service_data = Service({
        "name": service,
        "enabled": True,
        "category": SERVICES[service][0],
        "stage": SERVICES[service][1],
        "version": "4.0.0",
        "docker_config": {
            "image": f"cccs/alsvc_{service.lower()}:latest",
        },
    })
    assert resp == service_data.as_primitives(strip_null=True)


# noinspection PyUnusedLocal
def test_get_service_constants(datastore, login_session):
    _, session = login_session

    test_data = {
        'stages': config.services.stages,
        'categories': config.services.categories,
    }
    resp = get_api_data(session, f"{HOST}/api/v4/service/constants/")
    assert resp == test_data


# noinspection PyUnusedLocal
def test_get_all_services(datastore, login_session):
    _, session = login_session

    svc_list = sorted(list(SERVICES.keys()))
    resp = get_api_data(session, f"{HOST}/api/v4/service/all/")
    assert len(resp) == len(svc_list)
    for svc in resp:
        assert svc['name'] in svc_list


# noinspection PyUnusedLocal
def test_delete_service(datastore, login_session):
    _, session = login_session

    service = random.choice(list(SERVICES.keys()))
    resp = get_api_data(session, f"{HOST}/api/v4/service/{service}/", method="DELETE")
    assert resp['success']

    ds.service_delta.commit()
    delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)

    assert delta_data['total'] == (len(SERVICES) - 1)
    for svc in delta_data['items']:
        assert svc['id'] != service

    ds.service.commit()
    svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    assert (svc_data['total'] / 2) == (len(SERVICES) - 1)
    for svc in svc_data['items']:
        assert svc['id'] != service

    SERVICES.pop(service, None)

# noinspection PyUnusedLocal
def test_edit_service(datastore, login_session):
    _, session = login_session

    delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)
    svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    service = random.choice(list(SERVICES.keys()))
    service_data = Service({
        "name": service,
        "enabled": True,
        "category": SERVICES[service][0],
        "stage": SERVICES[service][1],
        "version": "3.3.0",
        "docker_config": {
            "image": f"cccs/alsvc_{service.lower()}:latest",
        },
    }).as_primitives()
    resp = get_api_data(session, f"{HOST}/api/v4/service/{service}/", method="POST", data=json.dumps(service_data))
    assert resp['success']

    ds.service_delta.commit()
    ds.service.commit()

    new_delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)
    new_svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    assert new_delta_data != delta_data
    assert new_svc_data == svc_data
    for svc in new_delta_data['items']:
        if svc['id'] == service:
            assert svc['version'] == '3.3.0'
        else:
            assert svc['version'] == '4.0.0'
