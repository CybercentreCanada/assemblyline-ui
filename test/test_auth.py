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
from conftest import APIError, get_api_data, host


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
    data = get_api_data(session, f"{host}/api/v4/auth/login/",
                        params={'user': 'ldap_user', 'password': 'ldap_password'})

    assert data['username'] == 'ldap_user'

def test_oauth_login(host):
    # Obtain an access token for the 'admin' user in Keycloak using the password grant type
    oauth_token = requests.post("http://localhost:8080/realms/master/protocol/openid-connect/token", data={
    "grant_type": "password",
    "username": "admin",
    "password": "admin",
    "client_secret": "assemblyline",
    "client_id": "assemblyline",
    "scope": "openid email profile"
}).json()['access_token']

    # Initialize a session
    session = requests.Session()

    # Login to the API and establish an authenticated session
    data = get_api_data(session, f"{host}/api/v4/auth/login/", params={'oauth_token': oauth_token})

    # Assert that the expected user is logged into the system
    assert data['username'] == "admin-keycloak"


def test_oauth_obo(host, datastore_connection):
    # Get a token for a middle-tier service (Clue) for the "admin-keycloak" user
    clue_token = requests.post("http://localhost:8080/realms/master/protocol/openid-connect/token", data={
        "grant_type": "password",
        "username": "admin",
        "password": "admin",
        "client_secret": "clue",
        "client_id": "clue",
    }).json()['access_token']

    # Exchange it for a token for the resource server (Assemblyline) to facilitate On-Behalf-Of (OBO)
    # Client is setup with custom scopes that limit it's authorized interaction with Assemblyline
    al_token = requests.post("http://localhost:8080/realms/master/protocol/openid-connect/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": clue_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_secret": "clue",
        "client_id": "clue",
    }).json()['access_token']

    # Use that token to allow the Clue to login to Assemblyline OBO the Keycloak user for a persistent session
    session = requests.Session()
    data = get_api_data(session, f"{host}/api/v4/auth/login/", method="POST", data=json.dumps({
        'oauth_token': al_token
    }))

    # Verify that the expected user is logged into the system
    assert data['username'] == "admin-keycloak"

    # Verify the the roles assigned for this session is limited based on what's defined by default for the client
    assert sorted(data['roles_limit']) == ['alert_view', 'badlist_view', 'safelist_view','submission_view']

    # Check that the role limit applied to the middle-tier server is enforced even though the user has more access (ie. create submissions)
    user = datastore_connection.user.get(data['username'], as_obj=False)

    # User's should never be granted additional access via a middle-tier service that they wouldn't have directly
    assert len(user['roles']) > len(data['roles_limit'])

    # Roles given to the session should be a subset of the user's permissions in Assemblyline
    assert set(data['roles_limit']).issubset(set(user['roles']))

    # For this test, verify that the user does have the ability to create submissions in Assemblyline normally
    assert 'submission_create' in user['roles']

    # Assert that any attempt to create a submission will raise a permission issue from the API
    with pytest.raises(APIError,
                       match="requires one of the following roles: submission_create"):
        get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps({
            'url': 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md',
            'name': 'README.md'
        }))

    # The middle-tier should be allowed to request additional scopes for incremental privileged escalation
    # In this example, we want to grant the middle-tier service to be able to create submissions on the user's behalf along with the other default roles
    al_extended_token = requests.post("http://localhost:8080/realms/master/protocol/openid-connect/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": clue_token,
        "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_secret": "clue",
        "client_id": "clue",
        "scope": "assemblyline_submission_create"
    }).json()['access_token']

    data = get_api_data(session, f"{host}/api/v4/auth/login/", method="POST", data=json.dumps({
        'oauth_token': al_extended_token
    }))

    # Verify that we have an additional role to create submissions through the middle-tier service
    assert sorted(data['roles_limit']) == ['alert_view', 'badlist_view', 'safelist_view', 'submission_create', 'submission_view']

    # We should now be able to perform a submission to Assemblyline with our extended privilege
    data = get_api_data(session, f"{host}/api/v4/submit/", method="POST", data=json.dumps({
            'url': 'https://raw.githubusercontent.com/CybercentreCanada/assemblyline-ui/master/README.md',
            'name': 'README.md',
            'submission_profile': 'static'
    }))
    assert 'sid' in data



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


@pytest.mark.parametrize("malicious_email,should_block", [
    ("*@assemblyline.cyber.gc.ca", True),
    ("admin?@assemblyline.cyber.gc.ca", True),
    ("admin/@assemblyline.cyber.gc.ca", True),
    ("admin@assemblyline.cyber.gc.ca", False),
    ("user.name+tag@assemblyline.cyber.gc.ca", False),
], ids=[
    "wildcard_star_blocked",
    "wildcard_question_blocked",
    "slash_blocked",
    "normal_email_allowed",
    "special_safe_chars_allowed",
])
def test_safe_email_validation(malicious_email, should_block):
    """Verify _is_safe_email blocks Lucene metacharacters that pass is_valid_email."""
    from assemblyline.common.net import is_valid_email
    from assemblyline_ui.api.v4.authentication import _is_safe_lucene_email

    if should_block:
        # These pass structural validation but contain Lucene metacharacters
        assert is_valid_email(malicious_email), f"{malicious_email} should be structurally valid"
        assert not _is_safe_lucene_email(
            malicious_email), f"{malicious_email} should be blocked by _is_safe_lucene_email"
    else:
        assert _is_safe_lucene_email(malicious_email), f"{malicious_email} should be allowed"


@pytest.mark.parametrize("malicious_email", [
    "*@assemblyline.cyber.gc.ca",
    "admin?@assemblyline.cyber.gc.ca",
], ids=[
    "wildcard_at_domain",
    "single_char_wildcard",
])
def test_signup_rejects_lucene_injection(datastore, host, malicious_email):
    """Verify that signup rejects emails with Lucene wildcards before the query runs.

    These payloads pass is_valid_email (structurally valid) but contain Lucene
    metacharacters. Without _is_safe_email, they would reach STORAGE.user.search.
    """
    session = requests.Session()

    with pytest.raises(APIError, match="Invalid email address"):
        get_api_data(
            session, f"{host}/api/v4/auth/signup/",
            method="POST",
            data=json.dumps({
                "user": "testlucene",
                "password": "TestPass123!@#",
                "password_confirm": "TestPass123!@#",
                "email": malicious_email,
            })
        )


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


def test_user_otp(datastore, login_user_session):
    user_info, session, host = login_user_session
    username = "user"
    assert user_info["username"] == username

    # None admin user should not be able to use the unset_otp endpoint
    with pytest.raises(APIError):
        get_api_data(session, f"{host}/api/v4/auth/unset_otp/name-not-exist/")


def test_reset_link_no_email_enumeration(datastore, host):
    # The goal of this test is to make sure that the get_reset_link endpoint does not allow for email enumeration,
    # meaning it should return the same response regardless of whether the email exists in the system or not. This is
    # important for security reasons, as allowing email enumeration can help attackers identify valid accounts.
    session = requests.Session()

    valid_resp = get_api_data(
        session, f"{host}/api/v4/auth/get_reset_link/",
        method="POST",
        data=json.dumps({"email": "admin@assemblyline.cyber.gc.ca"})
    )

    invalid_resp = get_api_data(
        session, f"{host}/api/v4/auth/get_reset_link/",
        method="POST",
        data=json.dumps({"email": "nonexistent@example.com"})
    )

    empty_resp = get_api_data(
        session, f"{host}/api/v4/auth/get_reset_link/",
        method="POST",
        data=json.dumps({"email": ""})
    )

    assert valid_resp == {"success": True}
    assert invalid_resp == {"success": True}
    assert empty_resp == {"success": True}
