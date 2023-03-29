import pytest

from requests import Response

from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_ui.app import app
from assemblyline_ui.config import config, CLASSIFICATION

CLASSIFICATION.enforce = True


@pytest.fixture()
def test_client():
    """generate a test client with test configuration."""
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "virustotal", "url": "http://lookup_vt:8001"},
    ]
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def local_login_session(test_client):
    """Setup a login session for the test_client."""
    r = test_client.post("/api/v4/auth/login/", data={"user": "user", "password": "user"})
    for name, value in r.headers:
        if name == "Set-Cookie" and "XSRF-TOKEN" in value:
            # in form: ("Set-Cookie", "XSRF-TOKEN=<token>; Path=/")
            token = value.split(";")[0].split("=")[1]
            test_client.environ_base["HTTP_X_XSRF_TOKEN"] = token
    data = r.json["api_response"]
    yield data, test_client


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    """Setup users."""
    try:
        create_users(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


@pytest.fixture(scope="module")
def digest():
    """Fake sha256 digest for use across tests"""
    return "a" * 64


@pytest.fixture(scope="module")
def digest2():
    """Fake sha256 digest for use across tests"""
    return "b" * 64


@pytest.fixture()
def mock_404_response(mocker):
    """Not found response."""
    mock_404 = mocker.MagicMock(spec=Response)
    mock_404.status_code = 404
    mock_404.json.return_value = {
        "api_error_message": "No results",
        "api_response": "",
        "api_status_code": 404,
    }
    return mock_404


@pytest.fixture()
def mock_400_response(mocker):
    """Bad request response."""
    mock_400 = mocker.MagicMock(spec=Response)
    mock_400.status_code = 400
    mock_400.json.return_value = {
        "api_error_message": "Invalid indicator name: not_an_ioc_name",
        "api_response": "",
        "api_status_code": 400,
    }
    return mock_400


@pytest.fixture()
def mock_mb_hash_response(mocker, digest):
    """Hash found in Malware Bazaar."""
    # digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    mock_mb_response = mocker.MagicMock(spec=Response)
    mock_mb_response.status_code = 200
    mock_mb_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            digest: {
                "classification": "UNRESTRICTED",
                "link": f"https://bazaar.abuse.ch/sample/{digest}/",
            },
        },
        "api_status_code": 200,
    }
    return mock_mb_response


@pytest.fixture()
def mock_mb_imphash_response(mocker, digest, digest2):
    """Imphash found in Malware Bazaar."""
    mock_mb_response = mocker.MagicMock(spec=Response)
    mock_mb_response.status_code = 200
    mock_mb_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            digest: {
                "classification": "UNRESTRICTED",
                "link": f"https://bazaar.abuse.ch/sample/{digest}/",
            },
            digest2: {
                "classification": "UNRESTRICTED",
                "link": f"https://bazaar.abuse.ch/sample/{digest2}/",
            },
        },
        "api_status_code": 200,
    }
    return mock_mb_response


@pytest.fixture()
def mock_vt_hash_response(mocker, digest):
    """Hash found in Virustotal."""
    mock_vt_response = mocker.MagicMock(spec=Response)
    mock_vt_response.status_code = 200
    mock_vt_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "vt-hash": {
                "classification": "UNRESTRICTED",
                "link": f"https://www.virustotal.com/gui/search/{digest}/summary",
            },
        },
        "api_status_code": 200,
    }
    return mock_vt_response


@pytest.fixture()
def mock_get(mocker):
    """Return a mocker for the `get` method."""
    mock_session = mocker.patch("assemblyline_ui.api.v4.federated_lookup.Session", autospec=True)
    mock_get = mock_session.return_value.get
    return mock_get


# def test_lookup_valid(datastore, login_session):
#    _, session, host = login_session
#
#    resp = get_api_data(session, f"{host}/api/v4/federated_lookup/ioc/")
#    assert resp == ["TODO"]


def test_lookup_ioc_multi_hit(
        datastore, local_login_session, mock_get, mock_vt_hash_response, mock_mb_hash_response, digest):
    """Lookup a valid ioc type with multiple configured sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And a given hash exists in both sources

    When a user requests a lookup of a given hash
        And no filter is applied

    Then the user should receive multiple links to the sample
    """
    _, client = local_login_session

    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_vt_hash_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/ioc/hash/{digest}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
        ],
        "virustotal": [
            {"vt-hash": f"https://www.virustotal.com/gui/search/{digest}/summary"},
        ],
    }
    assert data == expected


def test_lookup_ioc_multi_hit_filter(
        datastore, local_login_session, mock_get, mock_mb_hash_response, digest):
    """Lookup a valid ioc type with multiple configured sources but place a filter.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And a given hash exists in both sources

    When a user requests a lookup of a given hash
        And a filter for a single source is applied

    Then the user should receive results from only the filtered source
    """
    _, client = local_login_session

    mock_get.return_value = mock_mb_hash_response

    # User requests a lookup with filter
    rsp = client.get(f"/api/v4/federated_lookup/ioc/hash/{digest}/", query_string={"sources": "malware_bazaar"})

    # A query for each source should be sent
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
        ],
    }
    assert data == expected


def test_lookup_ioc_multi_source_single_hit(
        datastore, local_login_session, mock_get, mock_mb_hash_response, digest, mock_404_response):
    """Lookup a valid ioc type with multiple configured sources but found in only one source.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And a given hash exists only in Malware Bazaar

    When a user requests a lookup of a given hash
        And no filter is applied

    Then the user should receive results from only Malware Bazaar with no error
    """
    _, client = local_login_session

    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_404_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/ioc/hash/{digest}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
        ],
    }
    assert data == expected


def test_lookup_ioc_multi_source_invalid_single(
        datastore, local_login_session, mock_get, mock_mb_imphash_response, digest, digest2, mock_400_response):
    """With multiple configured sources look up an ioc that is valid in only one of those sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And `imphash` ioc type is only valid for Malware Bazaar
        And 2 entities in Malware Bazaar have the given `imphash`

    When a user requests a lookup of an `imphash`
        And no filter is applied

    Then the user should receive two results from only Malware Bazaar
        AND invalid IOC error message logged to error
    """
    _, client = local_login_session

    mock_get.side_effect = [
        mock_mb_imphash_response,
        mock_400_response,
    ]

    # User requests a lookup with no filter
    imphash = "a" * 32
    rsp = client.get(f"/api/v4/federated_lookup/ioc/imphash/{imphash}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
            {digest2: f"https://bazaar.abuse.ch/sample/{digest2}/"},
        ],
    }
    assert data == expected


def test_lookup_ioc_multi_source_invalid_all(
        datastore, local_login_session, mock_get, mock_400_response):
    """With multiple configured sources look up an ioc that is not valid in any of the sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And `notanioc` ioc type is not valid for Malware Bazaar or Virustotal

    When a user requests a lookup of an `notanioc`
        And no filter is applied

    Then the user should receive an empty list with no error
    """
    _, client = local_login_session

    mock_get.side_effect = [
        mock_400_response,
        mock_400_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get("/api/v4/federated_lookup/ioc/not_an_ioc_name/notanioc/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {}
    assert data == expected


def test_access_control_source_filtering(
        datastore, local_login_session, mock_get, mock_mb_hash_response, digest):
    """With multiple configured sources ensure access control filtering is applied at the source level.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And the given hash exists in both sources
        And Virustoal is a restricted classification

    When a user requests a lookup of a hash
        And no filter is applied
        And the user only has access to UNRESTRICTED results

    Then the user should receive only results from malware bazaar
    """
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "virustotal", "url": "http://lookup_vt:8001", "classification": "RESTRICTED"},
    ]
    _, client = local_login_session

    mock_get.return_value = mock_mb_hash_response

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/ioc/hash/{digest}/")

    # Only queries to access allowed sources should go through
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
        ],
    }
    assert data == expected


def test_access_control_ioc_filtering(
        datastore, local_login_session, mock_get, mock_mb_hash_response, digest, mocker):
    """With multiple configured sources ensure access control filtering is applied at the ioc level.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And the given hash exists in both sources
        And both sources are UNRESTRICTED
        And the ioc return from VirusTotal is RESTRICTED

    When a user requests a lookup of a hash
        And no filter is applied
        And the user only has access to UNRESTRICTED results

    Then the user should receive only results from malware bazaar
    """
    _, client = local_login_session

    mock_vt_response = mocker.MagicMock(spec=Response)
    mock_vt_response.status_code = 200
    mock_vt_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "vt-hash": {
                "classification": "RESTRICTED",
                "link": f"https://www.virustotal.com/gui/search/{digest}/summary",
            },
        },
        "api_status_code": 200,
    }
    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_vt_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/ioc/hash/{digest}/")

    # All queries sohuld be made
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": [
            {digest: f"https://bazaar.abuse.ch/sample/{digest}/"},
        ],
    }
    assert data == expected
