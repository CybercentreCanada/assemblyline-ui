import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.result import Result
from assemblyline.odm.randomizer import random_model_obj

NUM_ITEMS = 10
f_hash_list = []
ds = forge.get_datastore()


def purge_help():
    wipe_users(ds)
    ds.submission.wipe()
    ds.alert.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)

    for _ in range(NUM_ITEMS):
        a = random_model_obj(Alert)
        f_hash_list.append(a.file.sha256)
        ds.alert.save(a.alert_id, a)

    for _ in range(NUM_ITEMS):
        r = random_model_obj(Result)
        f_hash_list.append(r.sha256)
        ds.result.save(r.build_key(), r)

    ds.alert.commit()
    ds.submission.commit()

    request.addfinalizer(purge_help)
    return ds


# noinspection PyUnusedLocal
def test_list_data_sources(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/hash_search/list_data_sources/")
    assert resp == ['al', 'alert']


# noinspection PyUnusedLocal
def test_hash_search(datastore, login_session):
    _, session = login_session

    for _ in range(NUM_ITEMS):
        f_hash = random.choice(f_hash_list)
        resp = get_api_data(session, f"{HOST}/api/v4/hash_search/{f_hash}/")
        assert len(resp['alert']['items']) > 0 or len(resp['al']['items']) > 0
