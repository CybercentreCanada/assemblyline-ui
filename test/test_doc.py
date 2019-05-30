import pytest

from base import HOST, login_session, get_api_data

from assemblyline.common import forge
from assemblyline.odm.random_data import create_users, wipe_users

ds = forge.get_datastore()


def purge_doc():
    wipe_users(ds)


@pytest.fixture(scope="module")
def datastore(request):
    create_users(ds)
    request.addfinalizer(purge_doc)
    return ds


# noinspection PyUnusedLocal
def test_doc(datastore, login_session):
    _, session = login_session

    api_list = get_api_data(session, f"{HOST}/api/")
    assert len(api_list) > 0

    for api in api_list:
        resp = get_api_data(session, f"{HOST}/api/{api}/")
        assert 'apis' in resp and 'blueprints' in resp

