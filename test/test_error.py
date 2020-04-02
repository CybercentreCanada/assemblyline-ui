
import pytest

from assemblyline.odm.models.error import Error
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users

from conftest import HOST, get_api_data

NUM_ERRORS = 10
test_error = None


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        global test_error

        create_users(datastore_connection)
        for _ in range(NUM_ERRORS):
            e = random_model_obj(Error)
            if test_error is None:
                test_error = e
            datastore_connection.error.save(e.build_key(), e)
        datastore_connection.error.commit()
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        datastore_connection.error.wipe()


# noinspection PyUnusedLocal
def test_get_error(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/error/{test_error.build_key()}/")
    err = Error(resp)
    assert err == test_error


# noinspection PyUnusedLocal
def test_list_error(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/error/list/")
    assert resp['total'] == NUM_ERRORS
