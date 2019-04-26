import pytest

# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users, create_services, wipe_services

from assemblyline.common import forge

ds = forge.get_datastore()


def purge_help():
    wipe_users(ds)
    wipe_services(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    create_services(ds)
    request.addfinalizer(purge_help)
    return ds



# noinspection PyUnusedLocal
def test_classification_definition(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/help/classification_definition/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_classification_configuration(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/help/configuration/")
    assert isinstance(resp, dict)


# noinspection PyUnusedLocal
def test_classification_constants(datastore, login_session):
    _, session = login_session

    resp = get_api_data(session, f"{HOST}/api/v4/help/constants/")
    assert isinstance(resp, dict)
