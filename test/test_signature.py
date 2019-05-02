
import json
import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_signatures

from assemblyline.common import forge
from assemblyline.odm.models.signature import Signature
from assemblyline.odm.randomizer import random_model_obj

ds = forge.get_datastore()


def purge_signature():
    wipe_users(ds)
    ds.signature.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_signatures()
    request.addfinalizer(purge_signature)
    return ds


# noinspection PyUnusedLocal
def test_add_signature(datastore, login_session):
    _, session = login_session

    data = random_model_obj(Signature).as_primitives()
    resp = get_api_data(session, f"{HOST}/api/v4/signature/add/", data=json.dumps(data), method="PUT")
    assert resp == {'rev': 1, 'sid': 'CSE_000001', 'success': True}


# noinspection PyUnusedLocal
def test_change_status(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("meta.al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = signature['meta']['rule_id']
    rev = signature['meta']['rule_version']
    status = "DISABLED"

    resp = get_api_data(session, f"{HOST}/api/v4/signature/change_status/{sid}/{rev}/{status}/")
    assert resp['success']


# noinspection PyUnusedLocal
def test_delete_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("meta.al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = signature['meta']['rule_id']
    rev = signature['meta']['rule_version']

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/{rev}/", method="DELETE")
    assert resp['success']


# noinspection PyUnusedLocal
def test_download_signatures(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/signature/download/", raw=True)
    assert resp.decode(encoding="UTF-8").startswith("// Signatures last updated: ")


# noinspection PyUnusedLocal
def test_get_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("meta.al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = signature['meta']['rule_id']
    rev = signature['meta']['rule_version']

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/{rev}/")
    assert sid == resp['meta']['rule_id'] and rev == resp['meta']['rule_version'] and signature['name'] == resp['name']


# noinspection PyUnusedLocal
def test_list_signature(datastore, login_session):
    _, session = login_session

    ds.signature.commit()
    signature_count = ds.signature.search("id:*", rows=0)['total']

    resp = get_api_data(session, f"{HOST}/api/v4/signature/list/")
    assert resp['total'] == signature_count
    for sig in resp['items']:
        assert sorted(list(sig.keys())) == ['classification', 'id', 'meta', 'name']


# noinspection PyUnusedLocal
def test_set_signature(datastore, login_session):
    _, session = login_session

    signature = random.choice(ds.signature.search("meta.al_status:DEPLOYED", rows=100, as_obj=False)['items'])
    sid = signature['meta']['rule_id']
    rev = signature['meta']['rule_version']

    # Non revision bumping changes
    data = ds.signature.get(f"{sid}r.{rev}", as_obj=False)
    data['meta']['description'] = "NO REVISION CHANGE"
    data['comments'].append("NO REVISION CHANGE")

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/{rev}/", data=json.dumps(data), method="POST")
    assert resp == {'rev': rev, 'sid': sid, 'success': True}

    # Revision bumping changes
    data = ds.signature.get(f"{sid}r.{rev}", as_obj=False)
    data['meta']['description'] = "THIS SHOULD BE A NEW REVISION"
    data['comments'].append("THIS SHOULD BE A NEW REVISION")
    data['strings'].append('$added = "ADDING TRIGGER REVISION BUMP"')

    resp = get_api_data(session, f"{HOST}/api/v4/signature/{sid}/{rev}/", data=json.dumps(data), method="POST")
    assert resp == {'rev': rev+1, 'sid': sid, 'success': True}

# noinspection PyUnusedLocal
def test_signature_stats(datastore, login_session):
    _, session = login_session

    ds.signature.commit()
    signature_count = ds.signature.search("id:*", rows=0)['total']

    resp = get_api_data(session, f"{HOST}/api/v4/signature/stats/")
    assert len(resp) == signature_count
    for sig_stat in resp:
        assert sorted(list(sig_stat.keys())) == ['avg', 'classification', 'count', 'max', 'min', 'name', 'rev', 'sid']


# noinspection PyUnusedLocal
def test_update_available(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/signature/update_available/")
    assert resp == {'update_available': True}

    params = {'last_update': '2030-01-01T00:00:00.000000Z'}
    resp = get_api_data(session, f"{HOST}/api/v4/signature/update_available/", params=params)
    assert resp == {'update_available': False}
