
import json
import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.tc_signature import TCSignature
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_tc_signatures, wipe_tc_signatures


TEST_SIZE = 20
config = forge.get_config()
ds = forge.get_datastore(config)


def purge_tc_signature():
    wipe_tc_signatures(ds)
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_tc_signatures(ds)
    create_users(ds)

    request.addfinalizer(purge_tc_signature)
    return ds


# noinspection PyUnusedLocal
def test_add_tc_signature(datastore, login_session):
    _, session = login_session

    data = random_model_obj(TCSignature).as_primitives()
    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/", data=json.dumps(data), method="PUT")
    ds.tc_signature.commit()

    assert resp['success']
    assert resp['tc_id'].startswith("TC_")


# noinspection PyUnusedLocal
def test_change_status(datastore, login_session):
    _, session = login_session

    tc_signature = random.choice(ds.tc_signature.search("al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    tc_id = tc_signature['id']
    status = "DISABLED"

    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/change_status/{tc_id}/{status}/")
    ds.tc_signature.commit()

    assert resp['success']


# noinspection PyUnusedLocal
def test_delete_tc_signature(datastore, login_session):
    _, session = login_session

    tc_signature = random.choice(ds.tc_signature.search("al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    tc_id = tc_signature['id']

    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/{tc_id}/", method="DELETE")
    ds.tc_signature.commit()
    assert resp['success']


# noinspection PyUnusedLocal
def test_get_tc_signature(datastore, login_session):
    _, session = login_session

    tc_signature = random.choice(ds.tc_signature.search("id:*", rows=100, as_obj=False)['items'])
    tc_id = tc_signature['id']

    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/{tc_id}/")
    assert tc_signature['name'] == resp['name']
    assert tc_signature['al_status'] == resp['al_status']


# noinspection PyUnusedLocal
def test_set_tc_signature(datastore, login_session):
    _, session = login_session

    tc_signature = random.choice(ds.tc_signature.search("id:*", rows=100, as_obj=False)['items'])
    tc_id = tc_signature['id']

    # Non revision bumping changes
    data = ds.tc_signature.get(tc_id, as_obj=False)
    data['comment'] = "CHANGED THE SIGNATURE"
    data['values'].append("YEAH!")

    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/{tc_id}/", data=json.dumps(data), method="POST")
    ds.tc_signature.commit()
    assert resp == {'success': True}

    new_data = ds.tc_signature.get(tc_id, as_obj=False)

    assert new_data['comment'] == data['comment']
    assert new_data['values'] == data['values']
    assert new_data['last_modified'] != data['last_modified']


# noinspection PyUnusedLocal
def test_update_available(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/update_available/")
    assert resp == {'update_available': True}

    params = {'last_update': '2030-01-01T00:00:00.000000Z'}
    resp = get_api_data(session, f"{HOST}/api/v4/tc_signature/update_available/", params=params)
    assert resp == {'update_available': False}
