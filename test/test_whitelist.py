
import pytest
import random

from conftest import get_api_data, APIError

from assemblyline.odm.random_data import create_users, create_whitelists, wipe_users, wipe_whitelist


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_whitelists(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_whitelist(datastore_connection)


# noinspection PyUnusedLocal
def test_whitelist_exist(datastore, login_session):
    _, session, host = login_session

    hash = random.choice(datastore.whitelist.search("id:*", fl='id', rows=100, as_obj=False)['items'])['id']

    resp = get_api_data(session, f"{host}/api/v4/whitelist/{hash}/")
    assert resp == datastore.whitelist.get(hash, as_obj=False)


# noinspection PyUnusedLocal
def test_whitelist_missing(datastore, login_session):
    _, session, host = login_session

    hash = "DOES NOT EXISTS"

    with pytest.raises(APIError):
        get_api_data(session, f"{host}/api/v4/whitelist/{hash}/")
