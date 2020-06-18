
import random
import pytest

from conftest import get_api_data

from assemblyline.common import forge
from assemblyline.odm.random_data import create_users, wipe_users, create_heuristics, wipe_heuristics


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_heuristics(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_heuristics(datastore_connection)


def test_get_heuristics(datastore, login_session):
    _, session, host = login_session

    heuristic = random.choice(datastore.heuristic.search("id:*", rows=100, as_obj=False)['items'])
    resp = get_api_data(session, f"{host}/api/v4/heuristics/{heuristic['heur_id']}/")
    assert resp['classification'] == heuristic['classification']
    assert resp['description'] == heuristic['description']
    assert resp['filetype'] == heuristic['filetype']
    assert resp['heur_id'] == heuristic['heur_id']
    assert resp['name'] == heuristic['name']


def test_heuristic_stats(datastore, login_session):
    _, session, host = login_session
    cache = forge.get_statistics_cache()
    cache.delete()

    resp = get_api_data(session, f"{host}/api/v4/heuristics/stats/")
    assert len(resp) == 0

    stats = datastore.calculate_heuristic_stats()
    cache.set('heuristics', stats)

    heuristic_count = datastore.heuristic.search("id:*", rows=0)['total']
    resp = get_api_data(session, f"{host}/api/v4/heuristics/stats/")
    assert len(resp) == heuristic_count

    for sig_stat in resp:
        assert sorted(list(sig_stat.keys())) == ['avg', 'classification', 'count', 'heur_id', 'max', 'min', 'name']
