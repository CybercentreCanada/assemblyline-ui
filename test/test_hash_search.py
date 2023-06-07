import pytest
import requests

from conftest import get_api_data

from assemblyline.odm.models.alert import Alert
from assemblyline.odm.models.result import Result
from assemblyline.odm.models.file import File
from assemblyline.odm.randomizer import random_model_obj
from assemblyline.odm.random_data import create_users, wipe_users
from assemblyline_ui.app import app
from assemblyline_ui.config import config, CLASSIFICATION
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
    config.ui.external_sources = [
        {"name": "malware_bazaar", "url": "http://lookup_mb:8000"},
        {"name": "virustotal", "url": "http://lookup_vt:8001"},
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
        }
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
    ):
        # default to a single file
        if data is None:
            data = {}
            if source == "mb":
                data = {
                    "classification": CLASSIFICATION.UNRESTRICTED,
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
            "api_error_message": "",
            "api_response": [{
                "description": description,
                "malicious": malicious,
                "confirmed": confimred,
                "classification": classification,
                "data": data,
            }],
            "api_status_code": 200,
        }
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
def test_list_data_sources(datastore, login_session):
    _, session, host = login_session

    resp = get_api_data(session, f"{host}/api/v4/hash_search/list_data_sources/")
    assert resp == ['al', 'alert']


# noinspection PyUnusedLocal
def test_hash_search(datastore, login_session):
    _, session, host = login_session

    for x in range(NUM_ITEMS):
        resp = get_api_data(session, f"{host}/api/v4/hash_search/{f_hash_list[x]}/")
        assert len(resp['alert']['items']) > 0 and len(resp['al']['items']) > 0


def test_external_hash_multi_hit(datastore, user_login_session, mock_get, mock_lookup_success_response):
    """Lookup a valid hash with multiple configured sources.

    Given external lookups for both Malware Bazaar and Virustoal are configured
        And a given hash exists in both sources

    When a user requests an external hash search of the given hash
        And no filter is applied

    Then the user should receive a result from each source
    """
    _, client = user_login_session
    mock_get.side_effect = [
        mock_lookup_success_response(source="mb"),
        mock_lookup_success_response(source="vt"),
    ]

    digest_sha256 = "a" * 64
    # User requests a lookup with no filter
    rsp = client.get(f"/api/v4/hash_search/external/{digest_sha256}/")

    # A query for each source should be sent
    assert mock_get.call_count == 2
    # Expect correctly formatted mocked reponse
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    data["malware_bazaar"]["items"][0].pop("data")
    data["virustotal"]["items"][0].pop("data")
    expected = {
        "malware_bazaar": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
            }],
        },
        "virustotal": {
            "error": None,
            "items": [{
                "classification": CLASSIFICATION.UNRESTRICTED,
                "description": "Malware",
                "malicious": True,
                "confirmed": False,
            }],
        },
    }
    assert data == expected
