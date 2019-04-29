
import pytest

from assemblyline.common import forge
from assemblyline.odm.models.error import Error
from assemblyline.odm.randomizer import random_model_obj
# noinspection PyUnresolvedReferences
from base import HOST, login_session, get_api_data, create_users, wipe_users

NUM_ERRORS = 10
test_error = None
ds = forge.get_datastore()


def purge_error():
    wipe_users(ds)
    ds.error.wipe()


@pytest.fixture(scope="module")
def datastore(request):
    global test_error

    create_users(ds)
    for _ in range(NUM_ERRORS):
        e = random_model_obj(Error)
        if test_error is None:
            test_error = e
        ds.error.save(e.build_key(), e)
    ds.error.commit()

    request.addfinalizer(purge_error)
    return ds

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
