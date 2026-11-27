import warnings

import pytest
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_core import PAUSABLE_COMPONENTS
from conftest import get_api_data


@pytest.fixture(scope="module", autouse=True)
def users(datastore_connection):
    create_users(datastore_connection)
    yield
    wipe_users(datastore_connection)


def test_get_status_all(login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/system/status/ALL/")

    assert set(resp) == set(PAUSABLE_COMPONENTS)


def test_get_status_known_component(login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/system/status/dispatcher/")

    assert set(resp) == {"dispatcher"}


def test_get_status_unknown_component_is_not_found(login_session):
    _, session, host = login_session

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        res = session.get(f"{host}/api/v4/system/status/not_a_component/", verify=False)

    assert res.status_code == 404
    body = res.json()
    assert "not_a_component" in body["api_error_message"]
    assert body["api_response"] == {}
