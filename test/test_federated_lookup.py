import pytest

from urllib import parse as ul
from requests import Response

from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_ui.app import app
from assemblyline_ui.config import config, CLASSIFICATION
from assemblyline_ui.api.v4 import federated_lookup


@pytest.fixture()
def ext_config():
    """generate test configuration."""
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "virustotal", "url": "http://lookup_vt:8001"},
    ]
    original_tags = federated_lookup.all_supported_tags
    t = federated_lookup._Tags()
    t._all_supported_tags = {
        "malware_bazaar": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "file.pe.imports.imphash": CLASSIFICATION.UNRESTRICTED,
        },
        "virustotal": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.domain": CLASSIFICATION.UNRESTRICTED,
            "network.static.domain": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.ip": CLASSIFICATION.UNRESTRICTED,
            "network.static.ip": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.uri": CLASSIFICATION.UNRESTRICTED,
            "network.static.uri": CLASSIFICATION.UNRESTRICTED,
        },
    }
    # ensure local cache is always fresh for tests
    federated_lookup.all_supported_tags = t.all_supported_tags
    yield
    federated_lookup.all_supported_tags = original_tags


@pytest.fixture()
def test_client(ext_config):
    """generate a test client with test configuration."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def user_login_session(test_client):
    """Setup a login session for the test_client."""
    r = test_client.post("/api/v4/auth/login/", data={"user": "user", "password": "user"})
    for name, value in r.headers:
        if name == "Set-Cookie" and "XSRF-TOKEN" in value:
            # in form: ("Set-Cookie", "XSRF-TOKEN=<token>; Path=/")
            token = value.split(";")[0].split("=")[1]
            test_client.environ_base["HTTP_X_XSRF_TOKEN"] = token
    data = r.json["api_response"]
    yield data, test_client


@pytest.fixture()
def admin_login_session(test_client):
    """Setup a login session for the test_client."""
    r = test_client.post("/api/v4/auth/login/", data={"user": "admin", "password": "admin"})
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
def digest_sha256():
    """Fake sha256 digest for use across tests."""
    return "a" * 64


@pytest.fixture(scope="module")
def imphash():
    """Fake sha256 digest for use across tests."""
    return "b" * 32


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
        "api_error_message": "Client error",
        "api_response": "",
        "api_status_code": 400,
    }
    return mock_400


@pytest.fixture()
def mock_422_response(mocker):
    """Unprocessable content response."""
    mock_422 = mocker.MagicMock(spec=Response)
    mock_422.status_code = 422
    mock_422.json.return_value = {
        "api_error_message": "Invalid indicator name: not_an_ioc_name",
        "api_response": "",
        "api_status_code": 422,
    }
    return mock_422


@pytest.fixture()
def mock_mb_tags_response(mocker):
    """Tags supported by Malware Bazaar."""
    mock_mb_rsp = mocker.MagicMock(spec=Response)
    mock_mb_rsp.status_code = 200
    mock_mb_rsp.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "file.pe.imports.imphash": CLASSIFICATION.UNRESTRICTED,
        },
        "api_status_code": 200,
    }
    return mock_mb_rsp


@pytest.fixture()
def mock_vt_tags_response(mocker):
    """Tags supported by Virustotal."""
    mock_vt_rsp = mocker.MagicMock(spec=Response)
    mock_vt_rsp.status_code = 200
    mock_vt_rsp.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.domain": CLASSIFICATION.UNRESTRICTED,
            "network.static.domain": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.ip": CLASSIFICATION.UNRESTRICTED,
            "network.static.ip": CLASSIFICATION.UNRESTRICTED,
            "network.dynamic.uri": CLASSIFICATION.UNRESTRICTED,
            "network.static.uri": CLASSIFICATION.UNRESTRICTED,
        },
        "api_status_code": 200,
    }
    return mock_vt_rsp


@pytest.fixture()
def mock_mb_hash_response(mocker, digest_sha256):
    """Hash found in Malware Bazaar."""
    # digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    mock_mb_response = mocker.MagicMock(spec=Response)
    mock_mb_response.status_code = 200
    mock_mb_response.json.return_value = {
        "api_error_message": "",
        "api_response": [
            {
                "description": "description",
                "malicious": True,
                "confirmed": False,
                "classification": CLASSIFICATION.UNRESTRICTED,
                "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                "count": 1,
                "enrichment": [
                    {
                        "group": "group1",
                        "name": "name1",
                        "name_description": "",
                        "value": "value1",
                        "value_description": "value1 description",
                    },
                    {
                        "group": "group2",
                        "name": "name2",
                        "name_description": "name2 description",
                        "value": "value2",
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }
    return mock_mb_response


@pytest.fixture()
def mock_mb_imphash_response(mocker, imphash):
    """Imphash found in Malware Bazaar."""
    mock_mb_response = mocker.MagicMock(spec=Response)
    mock_mb_response.status_code = 200
    mock_mb_response.json.return_value = {
        "api_error_message": "",
        "api_response": [
            {
                "description": "description",
                "malicious": True,
                "confirmed": False,
                "classification": CLASSIFICATION.UNRESTRICTED,
                "link": f"https://bazaar.abuse.ch/browse.php?search=imphash%3A{imphash}",
                "count": 2,
                "enrichment": [
                    {
                        "group": "group1",
                        "name": "name1",
                        "name_description": "",
                        "value": "value1",
                        "value_description": "value1 description",
                    },
                    {
                        "group": "group2",
                        "name": "name2",
                        "name_description": "name2 description",
                        "value": "value2",
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }
    return mock_mb_response


@pytest.fixture()
def mock_vt_hash_response(mocker, digest_sha256):
    """Hash found in Virustotal."""
    mock_vt_response = mocker.MagicMock(spec=Response)
    mock_vt_response.status_code = 200
    mock_vt_response.json.return_value = {
        "api_error_message": "",
        "api_response": [
            {
                "description": "description",
                "malicious": True,
                "confirmed": False,
                "classification": CLASSIFICATION.UNRESTRICTED,
                "link": f"https://www.virustotal.com/gui/search?query={digest_sha256}",
                "count": 1,
                "enrichment": [
                    {
                        "group": "group1",
                        "name": "name1",
                        "name_description": "",
                        "value": "value1",
                        "value_description": "value1 description",
                    },
                    {
                        "group": "group2",
                        "name": "name2",
                        "name_description": "name2 description",
                        "value": "value2",
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }
    return mock_vt_response


@pytest.fixture()
def mock_get(mocker):
    """Return a mocker for the `get` method."""
    mock_session = mocker.patch("assemblyline_ui.api.v4.federated_lookup.Session", autospec=True)
    mock_get = mock_session.return_value.get
    return mock_get


def test_lookup_tag_multi_hit(
    datastore, user_login_session, mock_get, mock_vt_hash_response, mock_mb_hash_response, digest_sha256
):
    """Lookup a valid tag type with multiple configured sources.

    Given an external lookups for both Malware Bazaar and Virustoal are configured
        And a given hash exists in both sources

    When a user requests a lookup of a given hash
        And no filter is applied

    Then the user should receive a result from each source
    """
    _, client = user_login_session

    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_vt_hash_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/enrich/sha256/{digest_sha256}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "description": "description",
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                    "count": 1,
                    "confirmed": False,
                    "malicious": True,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                },
            ],
        },
        "virustotal": {
            "error": "",
            "items": [
                {
                    "description": "description",
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://www.virustotal.com/gui/search?query={digest_sha256}",
                    "count": 1,
                    "confirmed": False,
                    "malicious": True,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                },
            ],
        },
    }
    assert data == expected


def test_lookup_tag_multi_hit_filter(datastore, user_login_session, mock_get, mock_mb_hash_response, digest_sha256):
    """Lookup a valid tag type with multiple configured sources but place a filter.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And a given hash exists in both sources

    When a user requests a lookup of a given hash
        And a filter for a single source is applied

    Then the user should receive results from only the filtered source
    """
    _, client = user_login_session

    mock_get.return_value = mock_mb_hash_response

    # User requests a lookup with filter
    rsp = client.get(
        f"/api/v4/federated_lookup/enrich/sha256/{digest_sha256}/", query_string={"sources": "malware_bazaar"}
    )

    # A query for each source should be sent
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "description": "description",
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                    "count": 1,
                    "confirmed": False,
                    "malicious": True,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                },
            ],
        },
    }
    assert data == expected


def test_lookup_tag_multi_source_single_hit(
    datastore, user_login_session, mock_get, mock_mb_hash_response, digest_sha256, mock_404_response
):
    """Lookup a valid tag type with multiple configured sources but found in only one source.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And a given hash exists only in Malware Bazaar

    When a user requests a lookup of a given hash
        And no filter is applied

    Then the user should receive results from only Malware Bazaar with no error
    """
    _, client = user_login_session

    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_404_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/enrich/sha256/{digest_sha256}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "virustotal": {"error": "Not Found", "items": []},
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "description": "description",
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                    "count": 1,
                    "confirmed": False,
                    "malicious": True,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                },
            ],
        },
    }
    assert data == expected


def test_lookup_tag_multi_source_invalid_single(
    datastore, user_login_session, mock_get, mock_mb_imphash_response, imphash, mock_400_response
):
    """With multiple configured sources look up a tag that is valid in only one of those sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And `imphash` tag type is only valid for Malware Bazaar
        And two entities in Malware Bazaar have the given `imphash`

    When a user requests a lookup of an `imphash`
        And no filter is applied

    Then the user should receive a result from only Malware Bazaar with a count of 2
        AND invalid tag error message logged to error
    """
    _, client = user_login_session

    mock_get.side_effect = [
        mock_mb_imphash_response,
        mock_400_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/enrich/file.pe.imports.imphash/{imphash}/")

    # Only a query to malware bazaar should be sent as the tag is not valid for vt
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "description": "description",
                    "malicious": True,
                    "confirmed": False,
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=imphash%3A{imphash}",
                    "count": 2,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                }
            ],
        }
    }
    assert data == expected


def test_lookup_tag_multi_source_invalid_all(datastore, user_login_session, mock_get, mock_422_response):
    """With multiple configured sources look up a tag that is not valid in any of the sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And `not_a_tag` tag type is not valid for Malware Bazaar or Virustotal

    When a user requests a lookup of `not_a_tag`
        And no filter is applied

    Then the user should receive a 200 SUCCESS with no results found
    """
    _, client = user_login_session

    mock_get.side_effect = [
        mock_422_response,
        mock_422_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get("/api/v4/federated_lookup/enrich/not_a_tag/invalid/")

    # no queries should be sent to external sources
    assert mock_get.call_count == 0

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    success = rsp.json["api_response"]
    assert success == {}
    error = rsp.json["api_error_message"]
    assert error == ""


def test_access_control_source_filtering(
    datastore, user_login_session, mock_get, mock_mb_hash_response, digest_sha256
):
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
        {"name": "virustotal", "url": "http://lookup_vt:8001", "classification": CLASSIFICATION.RESTRICTED},
    ]
    _, client = user_login_session

    mock_get.return_value = mock_mb_hash_response

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/enrich/sha256/{digest_sha256}/")

    # Only queries to access allowed sources should go through
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                    "count": 1,
                    "description": "description",
                    "malicious": True,
                    "confirmed": False,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                }
            ],
        }
    }
    assert data == expected


def test_access_control_tag_filtering(
    datastore, user_login_session, mock_get, mock_mb_hash_response, digest_sha256, mocker
):
    """With multiple configured sources ensure access control filtering is applied at the tag level.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And the given hash exists in both sources
        And both sources are UNRESTRICTED
        And the tag returned from VirusTotal is RESTRICTED

    When a user requests a lookup of a hash
        And no filter is applied
        And the user only has access to UNRESTRICTED results

    Then the user should receive only results from malware bazaar
    """
    _, client = user_login_session

    mock_vt_response = mocker.MagicMock(spec=Response)
    mock_vt_response.status_code = 200
    mock_vt_response.json.return_value = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": CLASSIFICATION.RESTRICTED,
                "link": f"https://www.virustotal.com/gui/search?query={digest_sha256}",
                "count": 1,
                "description": "description",
                "malicious": True,
                "confirmed": False,
                "enrichment": [],
            }
        ],
        "api_status_code": 200,
    }
    mock_get.side_effect = [
        mock_mb_hash_response,
        mock_vt_response,
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/federated_lookup/enrich/sha256/{digest_sha256}/")

    # All queries should be made
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "virustotal": {"error": "", "items": []},
        "malware_bazaar": {
            "error": "",
            "items": [
                {
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "link": f"https://bazaar.abuse.ch/browse.php?search=sha256%3A{digest_sha256}",
                    "count": 1,
                    "description": "description",
                    "malicious": True,
                    "confirmed": False,
                    "enrichment": [
                        {
                            "group": "group1",
                            "name": "name1",
                            "name_description": "",
                            "value": "value1",
                            "value_description": "value1 description",
                        },
                        {
                            "group": "group2",
                            "name": "name2",
                            "name_description": "name2 description",
                            "value": "value2",
                            "value_description": "",
                        },
                    ],
                }
            ],
        },
    }
    assert data == expected


def test_access_control_tag_max_classification(datastore, admin_login_session, mock_get, imphash, mocker):
    """With multiple configured sources ensure access controls are applied to tags before searching.

    Given an external lookup for both Malware Bazaar and Assemblyline is configured
        And the given `imphash` value exists in both sources
        And the given `imphash` value is classified RESTRICTED
        And Assemblyline's maximum classification is RESTRICTED
        And Malware Bazaar's maximum classification is UNRESTRICTED

    When a user requests a lookup of the `imphash` value
        And no filter is applied
        And the user has access to RESTRICTED results

    Then the user should receive only results from Assemblyline
    """
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "assemblyline", "url": "http://lookup_al:8001", "max_classification": CLASSIFICATION.RESTRICTED},
    ]

    t = federated_lookup._Tags()
    t._all_supported_tags = {
        "malware_bazaar": {
            "file.pe.imports.imphash": CLASSIFICATION.UNRESTRICTED,
        },
        "assemblyline": {
            "file.pe.imports.imphash": CLASSIFICATION.UNRESTRICTED,
        },
    }
    federated_lookup.all_supported_tags = t.all_supported_tags

    data, client = admin_login_session

    mock_al_response = mocker.MagicMock(spec=Response)
    mock_al_response.status_code = 200
    al_lookup = [
        {
            "classification": CLASSIFICATION.RESTRICTED,
            "link": f'https://assemblyline-ui/search/result?query=result.sections.tags.file.pe.imports.imphash:"{imphash}"',
            "count": 2,
            "description": "description",
            "malicious": True,
            "confirmed": False,
            "enrichment": [],
        }
    ]
    mock_al_response.json.return_value = {
        "api_response": al_lookup,
        "api_error_message": "",
        "api_status_code": 200,
    }
    mock_get.return_value = mock_al_response

    # User requests a lookup with no filter
    clsf = ul.quote(CLASSIFICATION.RESTRICTED)
    rsp = client.get(f"/api/v4/federated_lookup/enrich/file.pe.imports.imphash/{imphash}/?classification={clsf}")

    # Only the query to AL should be made
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "malware_bazaar": {
            "error": "Tag classification exceeds max classification of source: malware_bazaar.",
            "items": [],
        },
        "assemblyline": {
            "error": "",
            "items": al_lookup,
        },
    }
    assert data == expected


def test_get_tag_names(datastore, ext_config, user_login_session, mock_get):
    """Lookup the valid tag names from all sources.

    Given external lookups for both Malware Bazaar and Virustoal are configured
        AND both sources are UNRESTRICTED

    When a user requests all valid tag names
        AND the user has access to UNRESTRICTED data

    Then the user should receive all tag names supported by both sources
    """
    _, client = user_login_session

    # User requests a tag lookup
    rsp = client.get("/api/v4/federated_lookup/tags/")

    # No queries should be sent as the cached data is mocked
    assert mock_get.call_count == 0

    data = rsp.json["api_response"]
    expected_data = {
        "malware_bazaar": ["md5", "sha1", "sha256", "file.pe.imports.imphash"],
        "virustotal": [
            "md5",
            "sha1",
            "sha256",
            "network.dynamic.domain",
            "network.static.domain",
            "network.dynamic.ip",
            "network.static.ip",
            "network.dynamic.uri",
            "network.static.uri",
        ],
    }
    assert data == expected_data


def test_get_tag_names_access_control(datastore, ext_config, user_login_session, mock_get):
    """Lookup the valid tag names with some sources restricted.

    Given external lookups for both Malware Bazaar and Virustoal are configured
        AND the malware_bazaar source is UNRESTRICTED
        AND the virutotal source is RESTRICTED

    When a user requests all valid tag names
        AND the user has access to UNRESTRICTED data

    Then the user should receive only tag names supported by malware_bazaar
    """
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "assemblyline", "url": "http://lookup_al:8001", "classification": CLASSIFICATION.RESTRICTED},
    ]

    _, client = user_login_session

    # User requests a tag lookup
    rsp = client.get("/api/v4/federated_lookup/tags/")

    # No queries should be sent as the cached data is mocked
    assert mock_get.call_count == 0

    data = rsp.json["api_response"]
    expected_data = {"malware_bazaar": ["md5", "sha1", "sha256", "file.pe.imports.imphash"]}
    assert data == expected_data


def test_get_all_tag_names(ext_config, mocker, mock_mb_tags_response, mock_vt_tags_response):
    """Generate the cache for valid tag names from all sources.

    Given external lookups for both Malware Bazaar and Virustoal are configured
        AND both sources are UNRESTRICTED

    When a request for all valid tag names is submitted

    Then the the local cache should receive all tag names supported by both sources
    """

    mock_session = mocker.MagicMock(autospec=True)
    mock_get = mock_session.get
    mock_get.side_effect = [
        mock_mb_tags_response,
        mock_vt_tags_response,
    ]
    t = federated_lookup._Tags()
    t.session = mock_session

    assert "malware_bazaar" in t.all_supported_tags
    assert mock_get.call_count == 2
    assert "virustotal" in t.all_supported_tags
    # no new calls should have been made as results are cached
    assert mock_get.call_count == 2
    assert len(t.all_supported_tags) == 2
