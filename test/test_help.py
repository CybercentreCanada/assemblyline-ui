import pytest

from conftest import get_api_data

from assemblyline.odm.random_data import create_users, wipe_users, create_services, wipe_services


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        create_services(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)
        wipe_services(datastore_connection)


# noinspection PyUnusedLocal
def test_classification_definition(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/help/classification_definition/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_configuration(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/help/configuration/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_constants(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/help/constants/")
    assert isinstance(resp, dict)
