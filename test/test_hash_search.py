import pytest
import requests

from conftest import get_api_data

from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.config import ExternalSource
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.file import File
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_ui.app import app
from assemblyline_ui.config import CLASSIFICATION
from assemblyline_ui.api.v4 import hash_search, federated_lookup

NUM_ITEMS = 10
f_hash_list = []


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    ds = datastore_connection
    try:
        create_users(ds)

        for _ in range(NUM_ITEMS):
            f = random_model_obj(File)
            f_hash_list.append(f.sha256)
            ds.file.save(f.sha256, f)

        for x in range(NUM_ITEMS):
            a = random_model_obj(Alert)
            a.file.sha256 = f_hash_list[x]
            ds.alert.save(a.alert_id, a)

        for x in range(NUM_ITEMS):
            r = random_model_obj(Result)
            r.sha256 = f_hash_list[x]
            ds.result.save(r.build_key(), r)

        ds.alert.commit()
        ds.file.commit()
        ds.submission.commit()

        yield ds
    finally:
        ds.alert.wipe()
        ds.file.wipe()
        ds.submission.wipe()
        wipe_users(ds)


@pytest.fixture()
def ext_config():
    """generate test configuration."""
    hash_search.external_sources = [
        ExternalSource({"name": "malware_bazaar", "url": "http://lookup_mb"}),
        ExternalSource({"name": "virustotal", "url": "http://lookup_vt"}),
    ]
    original_tags = hash_search.all_supported_tags
    t = federated_lookup._Tags()
    t._all_supported_tags = {
        "malware_bazaar": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "tlsh": CLASSIFICATION.UNRESTRICTED,
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
        "assemblyline": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.UNRESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "tlsh": CLASSIFICATION.UNRESTRICTED,
        },
        "internal_source": {
            "md5": CLASSIFICATION.UNRESTRICTED,
            "sha1": CLASSIFICATION.RESTRICTED,
            "sha256": CLASSIFICATION.UNRESTRICTED,
            "tlsh": CLASSIFICATION.UNRESTRICTED,
        },
    }
    # ensure local cache is always fresh for tests
    hash_search.all_supported_tags = t.all_supported_tags
    yield
    hash_search.all_supported_tags = original_tags


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


@pytest.fixture()
def mock_lookup_error_response(mocker):
    """Mock response for a generic error."""
    def _mock_lookup_error(
        *,
        error_message="No results.",
        status_code=404,
        response="",
    ):
        mock_response = mocker.MagicMock(spec=requests.Response)
        mock_response.status_code = status_code
        mock_response.json.return_value = {
            "api_response": response,
            "api_error_message": error_message,
            "api_status_code": status_code,
        }
        return mock_response
    return _mock_lookup_error


@pytest.fixture()
def mock_lookup_success_response(mocker):
    """Mock response for a generic lookup to that exists.

    # Response returns List of:
    [
        {
            "description": "",
            "malicious": <bool>,
            "confirmed": <bool>,
            "data": {...},
            "classification": <access control>,
        },
        ...,
    ]
    """
    def _mock_lookup_exists(
        *,
        description="Malware",
        malicious=True,
        confimred=False,
        data=None,
        classification=CLASSIFICATION.UNRESTRICTED,
        source="mb",
        additional_items=None,
    ):
        # default to a single file
        if data is None:
            data = {}
            if source == "mb":
                data = {
                    "sha256_hash": "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754",
                    "reporter": "abuse_ch",
                    "signature": "AZORult" if malicious else "",
                }
            elif source == "vt":
                data = {
                    "data": {
                        "attributes": {
                            "last_analysis_stats": {
                                "failure": 0,
                                "malicious": 3 if malicious else 0,
                                "suspicious": 1,
                                "undetected": 2
                            }
                        },
                    },
                }

        # create the default result
        r = {
            "api_error_message": None,
            "api_response": [{
                "description": description,
                "malicious": malicious,
                "confirmed": confimred,
                "classification": classification,
                "data": data,
            }],
            "api_status_code": 200,
        }
        if additional_items:
            r["api_response"].extend(additional_items)
        mock_response = mocker.MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = r
        return mock_response
    return _mock_lookup_exists


@pytest.fixture()
def mock_get(mocker):
    """Return a mocker for the `get` method."""
    mock_session = mocker.patch("assemblyline_ui.api.v4.hash_search.Session", autospec=True)
    mock_get = mock_session.return_value.get
    return mock_get


# noinspection PyUnusedLocal
def test_list_data_sources(datastore, user_login_session):
    _, client = user_login_session

    resp = client.get("/api/v4/hash_search/list_data_sources/")
    data = resp.json["api_response"]
    assert data == sorted(['al', 'alert', 'x.malware_bazaar', 'x.virustotal'])


# noinspection PyUnusedLocal
def test_hash_search(datastore, login_session):
    _, session, host = login_session

    for x in range(NUM_ITEMS):
        resp = get_api_data(session, f"{host}/api/v4/hash_search/{f_hash_list[x]}/")
        assert len(resp['alert']['items']) > 0 and len(resp['al']['items']) > 0


@pytest.mark.parametrize("digest", [
    "218d37ae955599538c3b36a160a122a0800bc64a552bce549a4a5ec24ec82dbe",
    "c5fd789462a4797944fb3d6712772a2be0758ad3",
    "9f2b90b4f0b5184a47187587afc1e321",
])
def test_external_hash_multi_hit(datastore, user_login_session, mock_get, mock_lookup_success_response, digest):
    """Lookup a valid hash with multiple configured sources.

    Given external lookups for both Malware Bazaar and Virustoal are configured
        And local lookups for `al` and `alert` are configured
        And the given hash type is valid for both sources
        And the given hash exists in both sources

    When a user requests an external hash search of the given hash
        And all sources are specified

    Then the user should receive a result from each source
    """
    _, client = user_login_session
    mock_get.side_effect = [
        mock_lookup_success_response(source=None),
        mock_lookup_success_response(source=None),
    ]

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/hash_search/{digest}/?db=al|alert|x.malware_bazaar|x.virustotal")

    # A query for each source should be sent
    assert mock_get.call_count == 2
    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "al": {"error": None, "items": []},
        "alert": {"error": None, "items": []},
        "x.malware_bazaar": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
        "x.virustotal": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
    }
    assert data == expected


def test_external_hash_multi_hit_filter(
        datastore, user_login_session, mock_get, mock_lookup_success_response):
    """Lookup a valid hash with multiple configured sources but place a filter.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And a given hash exists in both sources

    When a user requests a lookup of a given hash
        And a filter for a single source of malware_bazaar is applied

    Then the user should receive results from only the filtered source, malware_bazaar
    """
    _, client = user_login_session

    mock_get.return_value = mock_lookup_success_response(source=None)

    # User requests a lookup with a filter
    rsp = client.get(
        f"/api/v4/hash_search/{'a' * 32}/",
        query_string={"db": "x.malware_bazaar"}
    )

    # only a single query to mb should be sent
    assert mock_get.call_count == 1
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "x.malware_bazaar": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
    }
    assert data == expected


def test_external_hash_filter_all(
        datastore, user_login_session, mock_get):
    """Lookup a valid hash with multiple configured sources but place a filter for a non-configured source.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And a given hash exists in both external sources

    When a user requests a lookup of a given hash
        And a filter for a source that is not configured, Assemblyline is applied

    Then the user should receive 0 results
    """
    _, client = user_login_session

    # User requests a lookup with a filter
    rsp = client.get(
        f"/api/v4/hash_search/{'a' * 32}/",
        query_string={"db": "x.assemblyline"}
    )
    # no external calls should be made
    assert mock_get.call_count == 0

    assert rsp.status_code == 404
    assert rsp.json["api_response"] == {}
    assert rsp.json["api_error_message"] == "File hash not found."


def test_external_hash_multi_source_single_hit(
        datastore, user_login_session, mock_get, mock_lookup_success_response, mock_lookup_error_response):
    """Lookup a valid hash type in multiple configured sources but found in only one source.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And the given hash exists only in Malware Bazaar

    When a user requests a lookup of a given hash
        And all sources are specified

    Then the user should receive results from both Malware Bazaar and Virustotal with no error
    But the Virustotal items should be empty
    """
    _, client = user_login_session

    # futures will resolve non-deterministically, so make sure to set the correct response
    def mock_return(*args, **kwargs):
        if args[0].startswith("http://lookup_mb"):
            return mock_lookup_success_response(source=None)
        return mock_lookup_error_response()

    mock_get.side_effect = mock_return

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/hash_search/{'a' * 32}/?db=al|alert|x.malware_bazaar|x.virustotal")

    # A query for each source should be sent
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "al": {"error": None, "items": []},
        "alert": {"error": None, "items": []},
        "x.virustotal": {"error": None, "items": []},
        "x.malware_bazaar": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
    }
    print(data)
    assert data == expected


def test_external_hash_multi_source_invalid_single(
        datastore, user_login_session, mock_get, mock_lookup_success_response, mock_lookup_error_response):
    """With multiple configured sources look up a hash type that is valid in only one of those sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And the `tlsh` hash type is only valid for Malware Bazaar
        And two entities in Malware Bazaar have the given `tlsh`

    When a user requests a lookup of the `tlsh` hash
        And only external sources are specified

    Then the user should receive a result from only Malware Bazaar with two items
        AND invalid tag error message logged to error
    """
    _, client = user_login_session

    # futures will resolve non-deterministically, so make sure to set the correct response
    def mock_return(*args, **kwargs):
        if args[0].startswith("http://lookup_mb"):
            return mock_lookup_success_response(
                source=None,
                additional_items=[{
                    "description": "Malware 2",
                    "malicious": True,
                    "confirmed": False,
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "data": {},
                }]
            )
        return mock_lookup_error_response(
            error_message="Invalid tag name",
            status_code=422,
            response=None,
        )

    mock_get.side_effect = mock_return

    # User requests a lookup with no filter
    tlsh = "T18114B8804B6514724B577E2A6B30A4A6DABE0E7482CD5A8BF45F7260F7DE6CCCCD1720"
    rsp = client.get(f"/api/v4/hash_search/{tlsh}/?db=x.malware_bazaar|x.virustotal")

    # A query for only sources where hash type is valid should be called
    assert mock_get.call_count == 1
    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "x.virustotal": {"error": "Unsupported hash type.", "items": []},
        "x.malware_bazaar": {
            "error": None,
            "items": [
                {
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "description": "Malware",
                    "malicious": True,
                    "confirmed": False,
                    "data": {},
                },
                {
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "description": "Malware 2",
                    "malicious": True,
                    "confirmed": False,
                    "data": {},
                },
            ],
        },
    }
    assert data == expected


def test_external_hash_multi_source_invalid_all(
        datastore, user_login_session, mock_get, mock_lookup_error_response):
    """With multiple configured sources look up hash type that is not valid in any of the sources.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And `customhash` hash type is not valid for Malware Bazaar or Virustotal

    When a user requests a lookup of `customhash`
        And all sources are specified

    Then the user should receive a not supported response
    """
    _, client = user_login_session

    mock_get.return_value = mock_lookup_error_response(
        error_message="Invalid tag name",
        status_code=422,
        response=None,
    )

    # User requests a lookup with no filter
    customhash = "QWERTY:ABCDABCD"
    rsp = client.get(f"/api/v4/hash_search/{customhash}/?db=al|alert|x.malware_bazaar|x.virustotal")

    # A query for only sources where hash type is valid should be called
    assert mock_get.call_count == 0
    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 400
    assert rsp.json["api_response"] == ""
    assert rsp.json["api_error_message"].startswith("Invalid hash")


def test_external_hash_multi_source_invalid_filtered(
        datastore, user_login_session, mock_get, mock_lookup_error_response):
    """With multiple configured sources look up hash type that is valid for a source, but that source is filtered.

    Given an external lookup for both Malware Bazaar and Virustoal is configured
        And local lookups for `al` and `alert` are configured
        And the `tlsh` hash type is only valid for Malware Bazaar

    When a user requests a lookup of the `tlsh` hash
        And a filter for only virustotal is applied

    Then the user should receive a not supported response
    """
    _, client = user_login_session

    mock_get.return_value = mock_lookup_error_response(
        error_message="Invalid tag name",
        status_code=422,
        response=None,
    )

    # User requests a lookup with no filter
    tlsh = "T18114B8804B6514724B577E2A6B30A4A6DABE0E7482CD5A8BF45F7260F7DE6CCCCD1720"
    rsp = client.get(
        f"/api/v4/hash_search/{tlsh}/",
        query_string={"db": "x.virustotal"}
    )

    # A query for only sources where hash type is valid should be called
    assert mock_get.call_count == 0
    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 422
    data = rsp.json["api_response"]
    expected = {
        "x.virustotal": {
            "error": "Unsupported hash type.",
            "items": [],
        },
    }
    assert data == expected


def test_access_control_source_filtering(
        datastore, user_login_session, mock_get, mock_lookup_success_response):
    """With multiple configured sources ensure access control filtering is applied at the source level.

    Given an external lookup for both Malware Bazaar and Assemblyline is configured
        And local lookups for `al` and `alert` are configured
        And the given hash exists in both sources
        And Assemblyline is a restricted classification

    When a user requests a lookup of a hash
        And all sources are specified
        And the user only has access to UNRESTRICTED results

    Then the user should receive only results from malware bazaar
    """
    hash_search.external_sources = [
        ExternalSource({"name": "malware_bazaar", "url": "http://lookup_mb"}),
        ExternalSource({
            "name": "assemblyline", "url": "http://lookup_al", "classification": CLASSIFICATION.RESTRICTED
        }),
    ]
    _, client = user_login_session

    mock_get.return_value = mock_lookup_success_response(source=None)

    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/hash_search/{'a' * 32}/?db=al|alert|x.malware_bazaar|x.virustotal")

    # Only queries to access allowed sources should go through
    assert mock_get.call_count == 1

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "al": {"error": None, "items": []},
        "alert": {"error": None, "items": []},
        "x.malware_bazaar": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
    }
    assert data == expected


def test_access_control_result_filtering(
        datastore, user_login_session, mock_get, mock_lookup_success_response):
    """With multiple configured sources ensure access control filtering is applied at the result level.

    Given an external lookup for both "InternalSource" and Assembline is configured
        And the given hash exists in both sources
        And both sources are UNRESTRICTED
        And one result returned from Assemblyline is RESTRICTED
        And one result returned from Assemblyline is UNRESTRICTED
        And one result returned from InternalSource is RESTRICTED

    When a user requests a lookup of a hash
        And all sources are specified
        And the user only has access to UNRESTRICTED results

    Then the user should receive only ONE result from Assemblyline
    """
    hash_search.external_sources = [
        ExternalSource({
            "name": "assemblyline", "url": "http://lookup_al", "max_classification": CLASSIFICATION.RESTRICTED
        }),
        ExternalSource({
            "name": "internal_source", "url": "http://lookup_is", "max_classification": CLASSIFICATION.RESTRICTED
        }),
    ]
    _, client = user_login_session

    # futures will resolve non-deterministically, so make sure to set the correct response
    def mock_return(*args, **kwargs):
        if args[0].startswith("http://lookup_al"):
            return mock_lookup_success_response(
                source=None,
                classification=CLASSIFICATION.RESTRICTED,
                additional_items=[{
                    "description": "Malware 2",
                    "malicious": True,
                    "confirmed": False,
                    "classification": CLASSIFICATION.UNRESTRICTED,
                    "data": {},
                }],
            )
        if args[0].startswith("http://lookup_is"):
            return mock_lookup_success_response(source=None, classification=CLASSIFICATION.RESTRICTED)

    mock_get.side_effect = mock_return

    # User requests a lookup with no filter
    tlsh = "T18114B8804B6514724B577E2A6B30A4A6DABE0E7482CD5A8BF45F7260F7DE6CCCCD1720"
    rsp = client.get(f"/api/v4/hash_search/{tlsh}/?db=x.assemblyline|x.internal_source")

    # All queries should be made
    assert mock_get.call_count == 2

    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "x.internal_source": {"error": None, "items": []},
        "x.assemblyline": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware 2",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
    }
    assert data == expected


def test_access_control_hash_type_max_classification(datastore, user_login_session, mock_get):
    """With multiple configured sources ensure access controls are applied to hash types before searching.

    Given an external lookup for InternalSource is configured
        And local lookups for `al` and `alert` are configured
        And the given `sha1` value exists in InternalSource
        And InsternalSource's maximum classification is RESTRICTED
        And InternalSource's classification is UNRESTRICTED
        And the `sha1` has type has a classification of RESTRICTED

    When a user requests a lookup of the `sha1`
        And a filter for only `InternalSource` is applied
        And the user does not have access to RESTRICTED results

    Then the user should not receive any results
    """
    hash_search.external_sources = [
        ExternalSource({
            "name": "internal_source", "url": "http://lookup_is", "max_classification": CLASSIFICATION.RESTRICTED
        }),
    ]
    _, client = user_login_session

    # User requests a lookup with no filter
    rsp = client.get(
        f"/api/v4/hash_search/{'a' * 40}/",
        query_string={"db": "x.internal_source"}
    )

    assert mock_get.call_count == 0
    assert rsp.status_code == 422
    data = rsp.json["api_response"]
    expected = {
        "x.internal_source": {
            "error": "Unsupported hash type.",
            "items": [],
        },
    }
    assert data == expected


def test_access_control_submit_hash_classification(
        datastore, admin_login_session, mock_get, mock_lookup_success_response):
    """With multiple configured sources ensure access controls are applied to hashes before searching.

    Given external lookups for Malware Bazaar and Assemblyline are configured
        And local lookups for `al` and `alert` are configured
        And the given `md5` value exists in both sources
        And the given `md5`'s classification is RESTRICTED
        And Malware Bazaar's max classification is UNRESTRICTED
        And Assemblyline's max classification is RESTRICTED
        And the given user has access to RESTRICTED classification data

    When a user requests a lookup of the `md5`
        And a filter for external Assemblyline and Malware Bazaar is applied

    Then the user should receive results only from Assemblyline
    """
    hash_search.external_sources = [
        ExternalSource({"name": "malware_bazaar", "url": "http://lookup_mb"}),
        ExternalSource(
            {"name": "assemblyline", "url": "http://lookup_al", "max_classification": CLASSIFICATION.RESTRICTED}),
    ]
    _, client = admin_login_session

    def mock_return(*args, **kwargs):
        if args[0].startswith("http://lookup_al"):
            return mock_lookup_success_response(source=None)
        return mock_lookup_error_response()

    mock_get.side_effect = mock_return

    # User requests a lookup with no filter
    rsp = client.get(
        f"/api/v4/hash_search/{'a' * 32}/",
        query_string={"classification": CLASSIFICATION.RESTRICTED, "db": "x.assemblyline|x.malware_bazaar"},
    )

    assert mock_get.call_count == 1
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    expected = {
        "x.assemblyline": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
                "data": {},
            }],
        },
        "x.malware_bazaar": {
            "error": "File hash classification exceeds max classification.",
            "items": []
        },
    }
    assert data == expected
