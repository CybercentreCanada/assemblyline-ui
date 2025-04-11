
import pytest
from conftest import APIError, get_api_data

from assemblyline.common.security import get_totp_token
from assemblyline.odm.models.user import ACL_MAP
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.odm.randomizer import get_random_hash


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


# noinspection PyUnusedLocal
def test_login(datastore, login_session):
    user_info, session, host = login_session
    assert user_info['username'] == "admin"

    resp = get_api_data(session, f"{host}/api/")
    assert isinstance(resp, list)

    resp = get_api_data(session, f"{host}/api/v4/auth/logout/")
    assert resp.get('success', False) is True

# noinspection PyUnusedLocal
def test_otp(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/auth/setup_otp/")
    secret_key = resp.get('secret_key', None)
    assert secret_key is not None

    resp = get_api_data(session, f"{host}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
    if not resp.get('success', False):
        resp = get_api_data(session, f"{host}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
        assert resp.get('success', False) is True

    resp = get_api_data(session, f"{host}/api/v4/auth/disable_otp/")
    assert resp.get('success', False) is True
