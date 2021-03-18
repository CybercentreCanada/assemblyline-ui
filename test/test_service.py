import json
import pytest
import random

from conftest import get_api_data

from assemblyline.odm.models.service import Service
from assemblyline.odm.randomizer import SERVICES
from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services

TEMP_SERVICES = SERVICES


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)


@pytest.fixture
def suricata_init_config(datastore, login_session):
    _, session, host = login_session
    service_conf = {
        "name": "Suricata",
        "enabled": True,
        "category": "Networking",
        "stage": "CORE",
        "version": "4.0.0",
        "docker_config": {
            "image": f"cccs/assemblyline-service-suricata:4.0.0.dev69",
        },
        "update_config": {
            "generates_signatures": True,
            "method": "run",
            "run_options": {
                "allow_internet_access": True,
                "command": ["python", "-m", "suricata_.suricata_updater"],
                "image": "${REGISTRY}cccs/assemblyline-service-suricata:4.0.0.dev69"
            },
            "sources": [
                {
                    "name": "old",
                    "pattern": ".*\\.rules",
                    "uri": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
                },
                {
                    "name": "old with space",
                    "pattern": ".*\\.rules",
                    "uri": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
                }
            ],
            "update_interval_seconds": 60  # Quarter-day (every 6 hours)
        }
    }

    service_data = Service(service_conf).as_primitives()
    resp = get_api_data(session, f"{host}/api/v4/service/Suricata/", method="POST", data=json.dumps(service_data))
    if resp['success']:
        datastore.service_delta.commit()
        datastore.service.commit()

        delta_sources = datastore.get_service_with_delta("Suricata", as_obj=False)['update_config']['sources']
        passed = delta_sources[0]['name'] == "old" and delta_sources[1]['name'] == "old_with_space"
        return passed, service_conf
    return False


def suricata_change_config(service_conf, login_session):
    _, session, host = login_session
    service_data = Service(service_conf).as_primitives()
    resp = get_api_data(session, f"{host}/api/v4/service/Suricata/", method="POST", data=json.dumps(service_data))
    return resp['success']


# noinspection PyUnusedLocal
def test_get_versions(datastore, login_session):
    _, session, host = login_session

    service = random.choice(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/versions/{service}/")
    assert resp == ['3.3.0', '4.0.0']


# noinspection PyUnusedLocal
def test_get_service(datastore, login_session):
    _, session, host = login_session

    service = random.choice(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/{service}/")
    service_data = datastore.get_service_with_delta(service, as_obj=False)
    assert resp == service_data


# noinspection PyUnusedLocal
def test_get_service_constants(datastore, login_session, config):
    _, session, host = login_session

    test_data = {
        'stages': config.services.stages,
        'categories': config.services.categories,
    }
    resp = get_api_data(session, f"{host}/api/v4/service/constants/")
    assert resp == test_data


# noinspection PyUnusedLocal
def test_get_all_services(datastore, login_session):
    _, session, host = login_session

    svc_list = sorted(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/all/")
    assert len(resp) == len(svc_list)
    for svc in resp:
        assert svc['name'] in svc_list


# noinspection PyUnusedLocal
def test_delete_service(datastore, login_session):
    global TEMP_SERVICES
    _, session, host = login_session

    ds = datastore
    service = random.choice([x for x in TEMP_SERVICES.keys() if x != 'Suricata'])
    resp = get_api_data(session, f"{host}/api/v4/service/{service}/", method="DELETE")
    assert resp['success']

    ds.service_delta.commit()
    delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)

    assert delta_data['total'] == (len(TEMP_SERVICES) - 1)
    for svc in delta_data['items']:
        assert svc['id'] != service

    ds.service.commit()
    svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    assert (svc_data['total'] / 2) == (len(TEMP_SERVICES) - 1)
    for svc in svc_data['items']:
        assert svc['id'] != service

    TEMP_SERVICES.pop(service, None)


# noinspection PyUnusedLocal
def test_edit_service(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)
    svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    service = random.choice(list(TEMP_SERVICES.keys()))
    service_data = Service({
        "name": service,
        "enabled": True,
        "category": TEMP_SERVICES[service][0],
        "stage": TEMP_SERVICES[service][1],
        "version": "3.3.0",
        "docker_config": {
            "image": f"cccs/alsvc_{service.lower()}:latest",
        },
    }).as_primitives()
    resp = get_api_data(session, f"{host}/api/v4/service/{service}/", method="POST", data=json.dumps(service_data))
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


def test_edit_service_source(datastore, login_session, suricata_init_config):
    ds = datastore
    config_initiated, service_conf = suricata_init_config

    assert config_initiated

    # Changed; add new, remove old
    service_conf['update_config']['sources'] = [{
        "name": "new",
        "pattern": ".*\\.rules",
        "uri": "https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz"
    }]

    config_changed = suricata_change_config(service_conf, login_session)
    assert config_changed

    ds.service_delta.commit()
    ds.service.commit()

    delta = ds.get_service_with_delta("Suricata", as_obj=False)

    new_found = False
    old_not_found = True
    for src in delta['update_config']['sources']:
        if src['name'] == "old":
            old_not_found = False
            break
        elif src['name'] == "new":
            new_found = True

    assert old_not_found and new_found


def test_remove_service_sources(datastore, login_session, suricata_init_config):
    ds = datastore
    config_initiated, service_conf = suricata_init_config

    assert config_initiated

    # Wipe all sources
    service_conf['update_config']['sources'] = []
    config_changed = suricata_change_config(service_conf, login_session)
    assert config_changed

    ds.service_delta.commit()
    ds.service.commit()

    delta = ds.get_service_with_delta("Suricata", as_obj=False)

    old_not_found = True
    for src in delta['update_config']['sources']:
        if src['name'] == "old":
            old_not_found = False
            break

    assert old_not_found
