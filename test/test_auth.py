import os
import pytest
import base64

from conftest import APIError, get_api_data

from assemblyline.common.security import get_totp_token
from assemblyline.odm.models.user import ACL_MAP
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline.odm.randomizer import get_random_hash


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    try:
        create_users(datastore_connection)

        # add a random otp_sk to user for testing
        username = "user"
        user_data = datastore_connection.user.get(username, as_obj=False)
        user_data["otp_sk"] = base64.b32encode(os.urandom(25)).decode("UTF-8")
        datastore_connection.user.save(username, user_data)

        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


# noinspection PyUnusedLocal
def test_login(datastore, login_session):
    user_info, session, host = login_session
    assert user_info["username"] == "admin"

    resp = get_api_data(session, f"{host}/api/")
    assert isinstance(resp, list)

    resp = get_api_data(session, f"{host}/api/v4/auth/logout/")
    assert resp.get("success", False) is True


# noinspection PyUnusedLocal
def test_otp(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/auth/setup_otp/")
    secret_key = resp.get("secret_key", None)
    assert secret_key is not None

    resp = get_api_data(session, f"{host}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
    if not resp.get("success", False):
        resp = get_api_data(session, f"{host}/api/v4/auth/validate_otp/{get_totp_token(secret_key)}/")
        assert resp.get("success", False) is True

    resp = get_api_data(session, f"{host}/api/v4/auth/disable_otp/")
    assert resp.get("success", False) is True

    # admin is able to use unset otp endpoint to remove OTP for another user
    username = "user"
    resp = get_api_data(session, f"{host}/api/v4/auth/unset_otp/{username}/")
    assert resp.get("success") is True

    datastore.user.commit()
    user = datastore.user.get(username)
    assert user["otp_sk"] is None

    # success is false when remove otp_sk for a none existent user
    resp = get_api_data(session, f"{host}/api/v4/auth/unset_otp/name-not-exist/")
    assert resp.get("success") is False

    # success is false if the user does not exist
    resp = get_api_data(session, f"{host}/api/v4/auth/unset_otp/not-real-name/")
    assert resp.get("success") is False


# noinspection PyUnusedLocal
def test_user_otp(datastore, login_user_session):
    user_info, session, host = login_user_session
    username = "user"
    assert user_info["username"] == username

    # None admin user should not be able to use the unset_otp endpoint
    with pytest.raises(APIError):
        get_api_data(session, f"{host}/api/v4/auth/unset_otp/name-not-exist/")
