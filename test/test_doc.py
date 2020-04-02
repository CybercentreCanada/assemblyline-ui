import pytest

from conftest import get_api_data

from assemblyline.odm.random_data import create_users, wipe_users


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


# noinspection PyUnusedLocal
def test_doc(datastore, login_session):
    _, session, host = login_session

    api_list = get_api_data(session, f"{host}/api/")
    assert len(api_list) > 0

    for api in api_list:
        resp = get_api_data(session, f"{host}/api/{api}/")
        assert 'apis' in resp and 'blueprints' in resp

