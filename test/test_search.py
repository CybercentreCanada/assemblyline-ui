
import pytest

from assemblyline.common.uid import get_random_id
from assemblyline.odm.models.heuristic import Heuristic
from assemblyline.odm.models.tc_signature import TCSignature
from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.file import File
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.submission import Submission
from assemblyline.odm.models.workflow import Workflow
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users, create_signatures

TEST_SIZE = 10
collections = ['alert', 'file', 'heuristic', 'result', 'signature', 'submission', 'tc_signature', 'workflow']

ds = forge.get_datastore()
file_list = []
signatures = []


def purge_result():
    ds.alert.wipe()
    ds.file.wipe()
    ds.result.wipe()
    ds.signature.wipe()
    ds.submission.wipe()
    ds.heuristic.wipe()
    ds.tc_signature.wipe()
    ds.workflow.wipe()
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    signatures.extend(create_signatures(ds))
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

    for x in range(TEST_SIZE):
        tc_id = f"TC_0000{x + 1:#02d}"
        ds.tc_signature.save(tc_id, random_model_obj(TCSignature))
    ds.tc_signature.commit()

    for x in range(TEST_SIZE):
        h = random_model_obj(Heuristic)
        ds.heuristic.save(h.heur_id, h)
    ds.heuristic.commit()

    for x in range(TEST_SIZE):
        w_id = get_random_id()
        w = random_model_obj(Workflow)
        ds.workflow.save(w_id, w)
    ds.workflow.commit()

    request.addfinalizer(purge_result)
    return ds


# noinspection PyUnusedLocal
def test_deep_search(datastore, login_session):
    _, session = login_session

    params = {
        "query": "id:*",
        "rows": 5
    }
    for collection in collections:
        params['deep_paging_id'] = "*"
        res = []
        while True:
            resp = get_api_data(session, f"{HOST}/api/v4/search/{collection}/", params=params)
            params['deep_paging_id'] = resp['next_deep_paging_id']
            if len(resp['items']) == 0:
                break
            res.extend(resp['items'])
        assert len(res) >= TEST_SIZE


# noinspection PyUnusedLocal
def test_facet_search(datastore, login_session):
    _, session = login_session

    for collection in collections:
        resp = get_api_data(session, f"{HOST}/api/v4/search/facet/{collection}/id/")
        assert len(resp) == TEST_SIZE
        for v in resp.values():
            assert isinstance(v, int)


# noinspection PyUnusedLocal
def test_grouped_search(datastore, login_session):
    _, session = login_session

    for collection in collections:
        resp = get_api_data(session, f"{HOST}/api/v4/search/grouped/{collection}/id/")
        assert resp['total'] >= TEST_SIZE
        for v in resp['items']:
            assert v['total'] == 1 and 'value' in v


# noinspection PyUnusedLocal
def test_histogram_search(datastore, login_session):
    _, session = login_session

    date_hist_map = {
        'alert': 'ts',
        'file': 'seen.first',
        'heuristic': False,
        'signature': 'meta.creation_date',
        'submission': 'times.submitted',
        'tc_signature': 'last_modified',
        'workflow': 'last_edit'
    }

    for collection in collections:
        hist_field = date_hist_map.get(collection, 'expiry_ts')
        if not hist_field:
            continue

        resp = get_api_data(session, f"{HOST}/api/v4/search/histogram/{collection}/{hist_field}/")
        for k, v in resp.items():
            assert k.startswith("2") and k.endswith("Z") and isinstance(v, int)

    int_hist_map = {
        'alert': 'al.score',
        'file': 'seen.count',
        'result': 'result.score',
        'signature': 'meta.rule_version',
        'submission': 'file_count',
        'heuristic': False,
        'tc_signature': False,
        'workflow': 'hit_count'
    }

    for collection in collections:
        hist_field = int_hist_map.get(collection, 'expiry_ts')
        if not hist_field:
            continue

        resp = get_api_data(session, f"{HOST}/api/v4/search/histogram/{collection}/{hist_field}/")
        for k, v in resp.items():
            assert isinstance(int(k), int) and isinstance(v, int)


# noinspection PyUnusedLocal
def test_get_fields(datastore, login_session):
    _, session = login_session

    for collection in collections:
        resp = get_api_data(session, f"{HOST}/api/v4/search/fields/{collection}/")
        for v in resp.values():
            assert list(v.keys()) == ['default', 'indexed', 'list', 'stored', 'type']


# noinspection PyUnusedLocal
def test_search(datastore, login_session):
    _, session = login_session

    for collection in collections:
        resp = get_api_data(session, f"{HOST}/api/v4/search/{collection}/", params={"query": "id:*"})
        assert TEST_SIZE <= resp['total'] == len(resp['items'])


# noinspection PyUnusedLocal
def test_stats_search(datastore, login_session):
    _, session = login_session

    int_map = {
        'alert': 'al.score',
        'file': 'seen.count',
        'result': 'result.score',
        'signature': 'meta.rule_version',
        'submission': 'file_count',
        'heuristic': False,
        'tc_signature': False,
        'workflow': 'hit_count'
    }

    for collection in collections:
        field = int_map.get(collection, False)
        if not field:
            continue

        resp = get_api_data(session, f"{HOST}/api/v4/search/stats/{collection}/{field}/")
        assert list(resp.keys()) == ['avg', 'count', 'max', 'min', 'sum']
        for v in resp.values():
            assert isinstance(v, int) or isinstance(v, float)
