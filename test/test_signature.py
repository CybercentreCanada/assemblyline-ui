import json
import pytest
import random

from conftest import get_api_data, APIError

from assemblyline.odm.models.service import UpdateSource
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_signatures, \
    wipe_signatures, create_services, wipe_services


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)
        create_signatures(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)
        wipe_signatures(datastore_connection)


# noinspection PyUnusedLocal
def test_add_signature_source(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    data = random_model_obj(UpdateSource).as_primitives()
    data['name'] = "_NEW_added_SOURCE_"

    invalid_service = random.choice(ds.service.search("NOT _exists_:update_config.generates_signatures",
                                                      rows=100, as_obj=False)['items'])
    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/signature/sources/{invalid_service['name']}/",
                            data=json.dumps(data), method="PUT")

    service = random.choice(ds.service.search("update_config.generates_signatures:true",
                                              rows=100, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/signature/sources/{service['name']}/",
                        data=json.dumps(data), method="PUT")
    assert resp['success']

    ds.service.commit()
    new_service_data = ds.get_service_with_delta(service['name'], as_obj=False)
    found = False
    for source in new_service_data['update_config']['sources']:
        if source['name'] == data['name']:
            found = True
            break

    assert found


# noinspection PyUnusedLocal
def test_add_update_signature(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    # Insert a dummy signature
    data = random_model_obj(Signature).as_primitives()
    data['status'] = "DEPLOYED"
    key = f'{data["type"]}_{data["source"]}_{data["signature_id"]}'
    resp = get_api_data(session, f"{host}/api/v4/signature/add_update/", data=json.dumps(data), method="PUT")
    assert resp == {'id': key, 'success': True}

    # Test the signature data
    ds.signature.commit()
    added_sig = ds.signature.get(key, as_obj=False)
    assert data == added_sig

    # Change the signature status
    resp = get_api_data(session, f"{host}/api/v4/signature/change_status/{key}/DISABLED/")
    ds.signature.commit()
    assert resp['success']

    # Update signature data
    new_sig_data = "NEW SIGNATURE DATA"
    data['data'] = new_sig_data
    resp = get_api_data(session, f"{host}/api/v4/signature/add_update/", data=json.dumps(data), method="POST")
    assert resp == {'id': key, 'success': True}

    # Remove state change data
    data.pop('status', None)
    data.pop('state_change_date', None)
    data.pop('state_change_user', None)

    # Test the signature data
    ds.signature.commit()
    modded_sig = ds.signature.get(key, as_obj=False)

    modded_sig.pop('state_change_date')
    # Was state kept?
    assert "DISABLED" == modded_sig.pop('status')
    # Was state_change_user kept?
    assert "admin" == modded_sig.pop('state_change_user')
    assert data == modded_sig


# noinspection PyUnusedLocal
def test_add_update_signature_many(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    # Insert a dummy signature
    source = "source"
    s_type = "type"
    sig_list = []
    for x in range(10):
        data = random_model_obj(Signature).as_primitives()
        data['signature_id'] = f"test_sig_{x}"
        data['name'] = f"sig_name_{x}"
        data['status'] = "DEPLOYED"
        data['source'] = source
        data['type'] = s_type
        sig_list.append(data)

    uri = f"{host}/api/v4/signature/add_update_many/?source={source}&sig_type={s_type}"
    resp = get_api_data(session, uri, data=json.dumps(sig_list), method="PUT")
    assert resp == {'errors': False, 'success': 10, 'skipped': []}

    # Test the signature data
    ds.signature.commit()
    data = random.choice(sig_list)
    key = f"{data['type']}_{data['source']}_{data['signature_id']}"
    added_sig = ds.signature.get(key, as_obj=False)
    assert data == added_sig

    # Change the signature status
    resp = get_api_data(session, f"{host}/api/v4/signature/change_status/{key}/DISABLED/")
    ds.signature.commit()
    assert resp['success']

    # Update signature data
    new_sig_data = "NEW SIGNATURE DATA"
    data['data'] = new_sig_data
    uri = f"{host}/api/v4/signature/add_update_many/?source={source}&sig_type={s_type}"
    resp = get_api_data(session, uri, data=json.dumps([data]), method="POST")
    assert resp == {'errors': False, 'success': 1, 'skipped': []}

    # Remove state change data
    data.pop('status', None)
    data.pop('state_change_date', None)
    data.pop('state_change_user', None)

    # Test the signature data
    ds.signature.commit()
    modded_sig = ds.signature.get(key, as_obj=False)

    modded_sig.pop('state_change_date')
    # Was state kept?
    assert "DISABLED" == modded_sig.pop('status')
    # Was state_change_user kept?
    assert "admin" == modded_sig.pop('state_change_user')
    assert data == modded_sig


# noinspection PyUnusedLocal
def test_change_status(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['source']}_{signature['signature_id']}"
    status = "DISABLED"

    resp = get_api_data(session, f"{host}/api/v4/signature/change_status/{sid}/{status}/")
    ds.signature.commit()

    assert resp['success']

    # Check if the status actually changed
    ds.signature.commit()
    modded_sig = ds.signature.get(sid, as_obj=False)
    assert "DISABLED" == modded_sig.pop('status')


# noinspection PyUnusedLocal
def test_delete_signature(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['source']}_{signature['signature_id']}"

    resp = get_api_data(session, f"{host}/api/v4/signature/{sid}/", method="DELETE")
    ds.signature.commit()
    assert resp['success']


# noinspection PyUnusedLocal
def test_delete_signature_source(datastore, login_session):
    _, session, host = login_session
    ds = datastore

    invalid_service = random.choice(ds.service.search("NOT _exists_:update_config.generates_signatures",
                                                      rows=100, as_obj=False)['items'])
    with pytest.raises(APIError):
        resp = get_api_data(session,
                            f"{host}/api/v4/signature/sources/{invalid_service['name']}/TEST_SOURCE/",
                            method="DELETE")

    service = random.choice(ds.service.search("update_config.generates_signatures:true",
                                              rows=100, as_obj=False)['items'])
    service_data = ds.get_service_with_delta(service['name'], as_obj=False)
    source_name = service_data['update_config']['sources'][0]['name']
    resp = get_api_data(session, f"{host}/api/v4/signature/sources/{service['name']}/{source_name}/", method="DELETE")
    assert resp['success']

    ds.service.commit()
    new_service_data = ds.get_service_with_delta(service['name'], as_obj=False)
    found = False
    for source in new_service_data['update_config']['sources']:
        if source['name'] == source_name:
            found = True

    assert not found


# noinspection PyUnusedLocal
def test_download_signatures(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/signature/download/", raw=True)
    assert resp.startswith(b"PK")
    assert b"YAR_SAMPLE" in resp
    assert b"ET_SAMPLE" in resp


# noinspection PyUnusedLocal
def test_get_signature(datastore, login_session):
    _, session, host = login_session

    signature = random.choice(datastore.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['source']}_{signature['signature_id']}"

    resp = get_api_data(session, f"{host}/api/v4/signature/{sid}/")
    assert sid == f"{resp['type']}_{resp['source']}_{resp['signature_id']}" and signature['name'] == resp['name']


# noinspection PyUnusedLocal
def test_get_signature_source(datastore, login_session):
    _, session, host = login_session

    services = datastore.service.search("update_config.generates_signatures:true", rows=100, as_obj=False)['items']

    resp = get_api_data(session, f"{host}/api/v4/signature/sources/")
    for service in services:
        assert service['name'] in list(resp.keys())


# noinspection PyUnusedLocal
def test_set_signature_source(datastore, login_session):
    _, session, host = login_session
    original_source = service_data = None

    for service in datastore.service.search("update_config.generates_signatures:true", rows=100, as_obj=False)['items']:
        service_data = datastore.get_service_with_delta(service['name'], as_obj=False)
        if len(service_data['update_config']['sources']) != 0:
            original_source = service_data['update_config']['sources'][0]
            break

    assert original_source
    assert service_data

    new_source = random_model_obj(UpdateSource).as_primitives()
    new_source['name'] = original_source['name']

    resp = get_api_data(session, f"{host}/api/v4/signature/sources/{service_data['name']}/{original_source['name']}/",
                        data=json.dumps(new_source), method="POST")
    assert resp['success']

    datastore.service.commit()
    new_service_data = datastore.get_service_with_delta(service_data['name'], as_obj=False)
    found = False
    for source in new_service_data['update_config']['sources']:
        # Drop status information from signature sources
        source.pop('status', None)
        if source['name'] == original_source['name']:
            found = True
            assert original_source != source
            if source.get('private_key', None) and source['private_key'].endswith("\n"):
                assert source['private_key'] != new_source['private_key']
                assert all(source[k] == new_source[k] for k in source.keys() if k != 'private_key')
            else:
                assert source == new_source
            break

    assert found


# noinspection PyUnusedLocal
def test_signature_stats(datastore, login_session):
    _, session, host = login_session

    datastore.calculate_signature_stats()

    signature_count = datastore.signature.search("id:*", rows=0)['total']
    resp = get_api_data(session, f"{host}/api/v4/signature/stats/")
    assert len(resp) == signature_count
    for sig_stat in resp:
        assert sorted(list(sig_stat.keys())) == ['avg', 'classification', 'count', 'first_hit', 'id',
                                                 'last_hit', 'max', 'min', 'name', 'source', 'sum', 'type']


# noinspection PyUnusedLocal
def test_update_available(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/signature/update_available/")
    assert resp == {'update_available': True}

    params = {'last_update': '2030-01-01T00:00:00.000000Z'}
    resp = get_api_data(session, f"{host}/api/v4/signature/update_available/", params=params)
    assert resp == {'update_available': False}
