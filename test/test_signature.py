
import json
import random

import pytest

from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_signatures, wipe_signatures

config = forge.get_config()
ds = forge.get_datastore(config)


def purge_signature():
    wipe_users(ds)
    wipe_signatures(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_signatures(ds)
    request.addfinalizer(purge_signature)
    return ds


# noinspection PyUnusedLocal
def test_add_signature(datastore, login_session):
    _, session = login_session

    data = random_model_obj(Signature).as_primitives()
    resp = get_api_data(session, f"{HOST}/api/v4/signature/add/", data=json.dumps(data), method="PUT")
    ds.signature.commit()

    assert resp == {'id': f'{data["type"]}_{data["signature_id"]}_{data["revision"]}', 'success': True}


# noinspection PyUnusedLocal
def test_change_status(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['signature_id']}_{signature['revision']}"
    status = "DISABLED"

    resp = get_api_data(session, f"{HOST}/api/v4/signature/change_status/{sid}/{status}/")
    ds.signature.commit()

    assert resp['success']


# noinspection PyUnusedLocal
def test_delete_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['signature_id']}_{signature['revision']}"

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/", method="DELETE")
    ds.signature.commit()
    assert resp['success']


# noinspection PyUnusedLocal
def test_download_signatures(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/signature/download/", raw=True)
    assert resp.startswith(b"PK")
    assert b".yar" in resp
    assert b"suricata" in resp


# noinspection PyUnusedLocal
def test_get_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['signature_id']}_{signature['revision']}"

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/")
    assert sid == f"{resp['type']}_{resp['signature_id']}_{resp['revision']}" and signature['name'] == resp['name']


# noinspection PyUnusedLocal
def test_set_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = f"{signature['type']}_{signature['signature_id']}_{signature['revision']}"

    # Non revision bumping changes
    data = ds.signature.get(sid, as_obj=False)
    data['order'] = 9999
    data['state_change_user'] = "BOB"

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/", data=json.dumps(data), method="POST")
    ds.signature.commit()

    assert resp == {'sid': sid, 'success': True}

    # Revision bumping changes
    new_data = ds.signature.get(sid, as_obj=False)

    assert new_data['order'] == 9999
    assert new_data['state_change_user'] == "BOB"


# noinspection PyUnusedLocal
def test_signature_stats(datastore, login_session):
    _, session = login_session

    signature_count = ds.signature.search("id:*", rows=0)['total']

    resp = get_api_data(session, f"{HOST}/api/v4/signature/stats/")
    assert len(resp) == signature_count
    for sig_stat in resp:
        assert sorted(list(sig_stat.keys())) == ['avg', 'classification', 'count', 'max',
                                                 'min', 'name', 'rev', 'sid', 'type']


# noinspection PyUnusedLocal
def test_update_available(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/signature/update_available/")
    assert resp == {'update_available': True}

    params = {'last_update': '2030-01-01T00:00:00.000000Z'}
    resp = get_api_data(session, f"{HOST}/api/v4/signature/update_available/", params=params)
    assert resp == {'update_available': False}
