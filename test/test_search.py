import json
import random

import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_signatures

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.error import Error
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.randomizer import random_model_obj

TEST_SIZE = 10
collections = ['alert', 'file', 'result', 'signature', 'submission']

ds = forge.get_datastore()
file_list = []
signatures = []

def purge_result():
    ds.alert.wipe()
    ds.file.wipe()
    ds.result.wipe()
    ds.signature.wipe()
    ds.submission.wipe()
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    signatures.extend(create_signatures())
    ds.signature.commit()

    for x in range(TEST_SIZE):
        f = random_model_obj(File)
        ds.file.save(f.sha256, f)
        file_list.append(f.sha256)
    ds.file.commit()

    for x in range(TEST_SIZE):
        a = random_model_obj(Alert)
        a.file.sha256 = file_list[x]
        ds.alert.save(a.alert_id, a)
    ds.alert.commit()

    for x in range(TEST_SIZE):
        r = random_model_obj(Result)
        r.sha256 = file_list[x]
        ds.result.save(r.build_key(), r)
    ds.result.commit()

    for x in range(TEST_SIZE):
        s = random_model_obj(Submission)
        for f in s.files:
            f.sha256 = file_list[x]
        ds.submission.save(s.sid, s)
    ds.submission.commit()

    request.addfinalizer(purge_result)
    return ds


# noinspection PyUnusedLocal
def test_deep_search(datastore, login_session):
    _, session = login_session

    for collection in collections:
        resp = get_api_data(session, f"{HOST}/api/v4/search/deep/{collection}/", params={"q": "id:*"})
        assert resp['length'] == TEST_SIZE


# noinspection PyUnusedLocal
def test_facet_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_grouped_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_histogram_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_inspect_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_get_fields(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0


# noinspection PyUnusedLocal
def test_stats_search(datastore, login_session):
    _, session = login_session

    assert 1 == 0
