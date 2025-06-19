import json
import random

import pytest
import yaml
from conftest import get_api_data

from assemblyline.common.version import BUILD_MINOR, FRAMEWORK_VERSION, SYSTEM_VERSION
from assemblyline.odm.models.service import Service
from assemblyline.odm.random_data import (
    create_services,
    create_users,
    wipe_services,
    wipe_users,
)
from assemblyline.odm.randomizer import SERVICES

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
    name = "Suricata"
    version = datastore.service.search("name:Suricata", fl="version", rows=1, as_obj=False)['items'][0]['version']
    service_conf = {
        "name": name,
        "enabled": True,
        "category": "Networking",
        "stage": "CORE",
        "version": version,
        "docker_config": {
            "image": f"cccs/assemblyline-service-suricata:{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.dev69",
        },
        "update_config": {
            "generates_signatures": True,
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
    resp = get_api_data(session, f"{host}/api/v4/service/{name}/", method="POST", data=json.dumps(service_data))
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


def clear_signature_source_statuses(service_config: dict):
    # Drop status information from signature sources
    [s.pop('status', None)for s in service_config.get('update_config', {}).get('sources', [])]


# noinspection PyUnusedLocal
@pytest.mark.parametrize("full", [True, False])
def test_backup_and_restore(datastore, login_session, full):
    _, session, host = login_session

    backup = get_api_data(session, f"{host}/api/v4/service/backup/?full={full}", raw=True)
    assert isinstance(backup, bytes)
    backup_data = yaml.safe_load(backup)
    assert isinstance(backup_data, dict)
    assert 'type' in backup_data
    assert 'server' in backup_data
    assert 'data' in backup_data

    service = random.choice(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/{service}/", method="DELETE")
    assert resp['success']
    datastore.service_delta.commit()
    assert datastore.service_delta.search(f"id:{service}", rows=0)['total'] == 0

    resp = get_api_data(session, f"{host}/api/v4/service/restore/", data=backup, method="PUT")
    datastore.service_delta.commit()
    assert datastore.service_delta.search(f"id:{service}", rows=0)['total'] == 1


# noinspection PyUnusedLocal
def test_get_versions(datastore, login_session):
    _, session, host = login_session

    service = random.choice(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/versions/{service}/")
    for v in resp:
        assert v.startswith(f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}")


# noinspection PyUnusedLocal
def test_get_service(datastore, login_session):
    _, session, host = login_session

    service = random.choice(list(TEMP_SERVICES.keys()))
    resp = get_api_data(session, f"{host}/api/v4/service/{service}/")
    service_data = datastore.get_service_with_delta(service, as_obj=False)
    # Drop status information from signature sources
    [s.pop('status', None) for s in resp.get('update_config', {}).get('sources', [])]

    # Make sure we do not compare the auto_update field has this field is modified by the API
    # to use the default system configuration if it is not set.
    service_data.pop('auto_update', None)
    resp.pop('auto_update', None)

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

    for svc in svc_data['items']:
        assert svc['name'] != service

    TEMP_SERVICES.pop(service, None)


# noinspection PyUnusedLocal
def test_edit_service(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    delta_data = ds.service_delta.search("id:*", rows=100, as_obj=False)
    svc_data = ds.service.search("id:*", rows=100, as_obj=False)

    target_version = f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}.1"
    query = f"name:({ ' OR '.join(TEMP_SERVICES.keys())}) AND version:{target_version}"
    service = ds.service.search(query, rows=1, as_obj=False)['items'][0]['name']

    service_data = Service({
        "name": service,
        "enabled": True,
        "category": TEMP_SERVICES[service][0],
        "stage": TEMP_SERVICES[service][1],
        "version": target_version,
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
            assert svc['version'] == target_version
        else:
            assert svc['version'].startswith(f"{FRAMEWORK_VERSION}.{SYSTEM_VERSION}.{BUILD_MINOR}")


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
