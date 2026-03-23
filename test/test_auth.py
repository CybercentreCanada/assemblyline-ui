import base64
import hashlib
import json
import os
import warnings

import pytest
import requests
from assemblyline.common.security import get_totp_token
from assemblyline.odm.models.apikey import get_apikey_id
from assemblyline.odm.random_data import DEV_APIKEY_NAME, create_users, wipe_users
from conftest import APIError, get_api_data


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
def test_internal_login(datastore, login_session):
    user_info, session, host = login_session
    assert user_info["username"] == "admin"

    resp = get_api_data(session, f"{host}/api/")
    assert isinstance(resp, list)

    resp = get_api_data(session, f"{host}/api/v4/auth/logout/")
    assert resp.get("success", False) is True

def test_ldap_login(host):
    # Assert that login via LDAP works
    session = requests.Session()
    data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'ldap_user', 'password': 'ldap_password'})

    assert data['username'] == 'ldap_user'

# TODO: Add tests for OAuth and SAML once we have a test setup for them
# def test_oauth_login(host):
#     # Assert that login via OAuth works
#     session = requests.Session()
#     data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'oauth_user', 'oauth_token_id': 'oauth_password'})

#     assert data['username'] == 'oauth_user'

# def test_saml_login(host):
#     # Assert that login via SAML works
#     session = requests.Session()
#     data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'user': 'saml_user', 'saml_token_id': 'saml_password'})

#     assert data['username'] == 'saml_user'

@pytest.mark.parametrize("is_active", [True, False], ids=["account_enabled", "account_disabled"])
def test_apikey(datastore, login_session, is_active):
    _, session, host = login_session

    apikey = datastore.apikey.get(get_apikey_id(DEV_APIKEY_NAME, "admin"))
    password = os.getenv("DEV_ADMIN_PASS", 'admin') or 'admin'

    if is_active:
        datastore.user.update("admin", [(datastore.user.UPDATE_SET, 'is_active', True)])
        datastore.user.commit()

        # Test authentication to the API using API keys
        get_api_data(session, f"{host}/api/v4/auth/login/", method="POST", data=json.dumps({
            "user": "admin",
            "apikey": f"{apikey.key_name}:{password}"
        }))

    else:
        # If a user account is disabled, they shouldn't be able to use an API key to authenticate
        datastore.user.update("admin", [(datastore.user.UPDATE_SET, 'is_active', False)])
        datastore.user.commit()

        with pytest.raises(APIError, match="This owner of this API Key is not active."):
            get_api_data(session, f"{host}/api/v4/auth/login/", method="POST", data=json.dumps({
                "user": "admin",
                "apikey": f"{apikey.key_name}:{apikey.password}"
            }))

        # Restore user account active status for the rest of tests
        datastore.user.update("admin", [(datastore.user.UPDATE_SET, 'is_active', True)])
        datastore.user.commit()


def _get_cache_key(username: str, apikey: str) -> str:
    return hashlib.sha256(f"{username}:{apikey}".encode()).hexdigest()


def test_apikey_caching(datastore, host):
    from assemblyline_ui.config import APIKEY_CACHE

    caching_enabled = APIKEY_CACHE.__class__.__name__ != "DummyCache"

    apikey = datastore.apikey.get(get_apikey_id(DEV_APIKEY_NAME, "admin"))
    password = os.getenv("DEV_ADMIN_PASS", "admin") or "admin"
    apikey_str = f"{apikey.key_name}:{password}"
    cache_key = _get_cache_key("admin", apikey_str)

    if caching_enabled:
        APIKEY_CACHE.remove(cache_key)

    session = requests.Session()
    headers = {"X-USER": "admin", "X-APIKEY": apikey_str}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        resp = session.get(f"{host}/api/v4/user/whoami/", headers=headers, verify=False)
    assert resp.status_code == 200

    if caching_enabled:
        assert APIKEY_CACHE.exist(cache_key), "API key should be cached after successful auth"
        APIKEY_CACHE.remove(cache_key)
    else:
        assert not APIKEY_CACHE.exist(cache_key), "API key should NOT be cached when caching is disabled"


def test_apikey_failed_auth_not_cached(datastore, host):
    from assemblyline_ui.config import APIKEY_CACHE

    caching_enabled = APIKEY_CACHE.__class__.__name__ != "DummyCache"

    cache_key = _get_cache_key("admin", "invalid:wrongpassword")

    if caching_enabled:
        APIKEY_CACHE.remove(cache_key)

    session = requests.Session()
    headers = {"X-USER": "admin", "X-APIKEY": "invalid:wrongpassword"}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        resp = session.get(f"{host}/api/v4/user/whoami/", headers=headers, verify=False)
    assert resp.status_code == 401

    assert not APIKEY_CACHE.exist(cache_key), "Failed auth should not be cached"


def test_apikey_caching_repeated_requests(datastore, host):
    from assemblyline_ui.config import APIKEY_CACHE

    caching_enabled = APIKEY_CACHE.__class__.__name__ != "DummyCache"

    apikey = datastore.apikey.get(get_apikey_id(DEV_APIKEY_NAME, "admin"))
    password = os.getenv("DEV_ADMIN_PASS", "admin") or "admin"
    apikey_str = f"{apikey.key_name}:{password}"
    cache_key = _get_cache_key("admin", apikey_str)

    if caching_enabled:
        APIKEY_CACHE.remove(cache_key)

    session = requests.Session()
    headers = {"X-USER": "admin", "X-APIKEY": apikey_str}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for i in range(3):
            resp = session.get(f"{host}/api/v4/user/whoami/", headers=headers, verify=False)
            assert resp.status_code == 200, f"Request {i+1} should succeed"

    if caching_enabled:
        assert APIKEY_CACHE.exist(cache_key), "API key should remain cached"
        APIKEY_CACHE.remove(cache_key)

    session = requests.Session()
    headers = {"X-USER": "admin", "X-APIKEY": apikey_str}

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        resp = session.get(f"{host}/api/v4/user/whoami/", headers=headers, verify=False)
    assert resp.status_code == 200

    if caching_enabled:
        assert APIKEY_CACHE.exist(cache_key), "API key should be cached after successful auth"
        APIKEY_CACHE.remove(cache_key)



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
