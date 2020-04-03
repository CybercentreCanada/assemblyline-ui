import pytest

from conftest import get_api_data

from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.file import File
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users

NUM_ITEMS = 10
f_hash_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    ds = datastore_connection
    try:
        create_users(ds)

        for x in range(NUM_ITEMS):
            f = random_model_obj(File)
            f_hash_list.append(f.sha256)
            ds.file.save(f.sha256, f)

        for x in range(NUM_ITEMS):
            a = random_model_obj(Alert)
            a.file.sha256 = f_hash_list[x]
            ds.alert.save(a.alert_id, a)

        for x in range(NUM_ITEMS):
            r = random_model_obj(Result)
            r.sha256 = f_hash_list[x]
            ds.result.save(r.build_key(), r)

        ds.alert.commit()
        ds.file.commit()
        ds.submission.commit()

        yield ds
    finally:
        ds.alert.wipe()
        ds.file.wipe()
        ds.submission.wipe()
        wipe_users(ds)


# noinspection PyUnusedLocal
def test_list_data_sources(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/hash_search/list_data_sources/")
    assert resp == ['al', 'alert']


# noinspection PyUnusedLocal
def test_hash_search(datastore, login_session):
    _, session, host = login_session

    for x in range(NUM_ITEMS):
        resp = get_api_data(session, f"{host}/api/v4/hash_search/{f_hash_list[x]}/")
        assert len(resp['alert']['items']) > 0 and len(resp['al']['items']) > 0
