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


def test_lookup_valid(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/federated_lookup/ioc/")
    assert resp == ["TODO"]


def test_lookup_hash_mb(datastore, login_session):
    _, session, host = login_session

    digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    rsp = get_api_data(
        session,
        f"{host}/api/v4/federated_lookup/ioc/hash/{digest}/")

    print(f"{rsp=}")
    assert rsp['sha256'] == 'asdf'
