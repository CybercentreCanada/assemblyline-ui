import json
import pytest
import random

from conftest import HOST, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.service import Service
from assemblyline.odm.randomizer import SERVICES
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services

config = forge.get_config()


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)


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
    service_data = datastore.get_service_with_delta(service, as_obj=False)
    assert resp == service_data


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
