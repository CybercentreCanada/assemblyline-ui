
import pytest

from assemblyline.common.security import get_totp_token
from assemblyline.odm.randomizer import get_random_hash
from assemblyline.odm.random_data import create_users, wipe_users

from conftest import get_api_data, APIError


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
def test_api_keys(datastore, login_session):
    _, session, host = login_session
    key_name = f'apikey_{get_random_hash(6)}'

    # Added a read apikey
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_r/READ/", method="PUT")
    read_pass = resp.get('apikey', None)
    assert read_pass is not None

    # Cannot reuse apikey names
    with pytest.raises(APIError):
        resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_r/READ_WRITE/", method="PUT")

    # Added a read/write key
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_rw/READ_WRITE/", method="PUT")
    read_write_pass = resp.get('apikey', None)
    assert read_write_pass is not None

    # Added a write key
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_w/WRITE/", method="PUT")
    write_pass = resp.get('apikey', None)
    assert write_pass is not None

    # Try to login with the read key
    resp = get_api_data(session, f"{host}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': read_pass})
    assert resp.get('privileges', []) == ['R']

    # Try to login with the read/write key
    resp = get_api_data(session, f"{host}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': read_write_pass})
    assert resp.get('privileges', []) == ["R", "W"]

    # Try to login with the write key
    resp = get_api_data(session, f"{host}/api/v4/auth/login/",
                        params={'user': 'admin', 'apikey': write_pass})
    assert resp.get('privileges', []) == ["W"]

    # Login with username and password so we are allowed to delete apikeys
    get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'admin', 'password': 'admin'})

    # Delete the read key
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_r/", method="DELETE")
    assert resp.get('success', False) is True

    # Delete the read/write key
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_rw/", method="DELETE")
    assert resp.get('success', False) is True

    # Delete the write key
    resp = get_api_data(session, f"{host}/api/v4/auth/apikey/{key_name}_w/", method="DELETE")
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
