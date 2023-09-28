from urllib import parse as ul

import pytest
import requests

from . import app as server


@pytest.fixture()
def test_client():
    """generate a test client."""
    orig = server.API_KEY
    server.API_KEY = "X"
    with server.app.test_client() as client:
        with server.app.app_context():
            server.app.config["TESTING"] = True
            yield client
    server.API_KEY = orig


@pytest.fixture()
def mock_lookup_error(mocker):
    """Customisable mock response for a lookup that errors."""
    def _mock_lookup_error(
        *,
        error_message="A generic server error",
        response="",
        status_code=500,
        server_version="4.4.0.0"
    ):

        r = {
            "api_error_message": error_message,
            "api_response": response,
            "api_server_version": server_version,
            "api_status_code": status_code,
        }

        mock_response = mocker.MagicMock()
        mock_response.status_code = status_code
        mock_response.json.return_value = r

        mock_session = mocker.patch.object(requests, "Session", autospec=True)
        mock_session.return_value.get.return_value = mock_response
        return r

    return _mock_lookup_error


@pytest.fixture()
def mock_lookup_success(mocker):
    """Mock response for a generic lookup that exists."""
    def _mock_lookup_exists(
        *,
        items=None,
        offset=0,
        rows=None,
        total=None,
        side_effect=None,
    ):
        # default to a single malicious file
        if items is None:
            items = [{
                "classification": "TLP:CLEAR",
                "id": "a" * 64,
                "result": {
                    "score": 1000,
                },
            }]
        if rows is None:
            rows = len(items)
        if total is None:
            total = len(items)

        # create the default result
        r = {
            "api_error_message": "",
            "api_response": {
                "items": items,
                "offset": offset,
                "rows": rows,
                "total": total,
            },
            "api_server_version": "4.4.0.0",
            "api_status_code": 200,
        }

        mock_response = mocker.MagicMock(spec=requests.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = r

        # setup mock response for a valid hash lookup
        mock_session = mocker.patch.object(requests, "Session", autospec=True)
        mock_session.return_value.get.return_value = mock_response
        if side_effect:
            mock_session.return_value.get.side_effect = side_effect
        return r["api_response"]

    return _mock_lookup_exists


def test_get_mappings(test_client):
    """Ensure tags are returned."""
    rsp = test_client.get("/tags/")
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == {tname: server.CLASSIFICATION for tname in sorted(server.TAG_MAPPING)}


def test_hash_found(test_client, mock_lookup_success):
    """Validate respone for a hash that exists."""
    data = mock_lookup_success()
    digest = data["items"][0]["id"]

    # sha256 can use the result index
    rsp = test_client.get(f"/search/sha256/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f'{server.URL_BASE}/search/result?query=sha256:"{digest}"',
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200, rsp.json["api_error_message"]
    assert rsp.json == expected

    # other hashes must use file index
    digest = "a" * 32
    rsp = test_client.get(f"/search/md5/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f'{server.URL_BASE}/search/file?query=md5:"{digest}"',
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200, rsp.json["api_error_message"]
    assert rsp.json == expected


def test_hash_dne(test_client, mock_lookup_success):
    """Validate respone for a hash that does not exists."""
    mock_lookup_success(items=[])

    rsp = test_client.get(f"/search/md5/{'a' * 32}/")
    expected = {
        "api_error_message": "No items found",
        "api_response": "",
        "api_status_code": 404,
    }
    assert rsp.status_code == 404
    assert rsp.json == expected

    # invalid hashes will not raise an error and will just not be found
    rsp = test_client.get("/search/md5/abc}/")
    expected = {
        "api_error_message": "No items found",
        "api_response": "",
        "api_status_code": 404,
    }
    assert rsp.status_code == 404
    assert rsp.json == expected


def test_error_conditions(test_client, mock_lookup_error):
    """Validate error handling."""
    mock_lookup_error()
    rsp = test_client.get(f"/search/md5/{'a' * 32}/")
    expected = {
        "api_error_message": "A generic server error",
        "api_response": "",
        "api_status_code": 500,
    }
    assert rsp.status_code == 500
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/search/abc/abc}/")
    assert rsp.status_code == 422
    assert rsp.json["api_error_message"].startswith("Invalid tag name: ")


def test_detailed_malicious(test_client, mock_lookup_success):
    """Test getting details for a valid tag that is found and is malicious."""
    data = mock_lookup_success()

    url = ul.quote("https://a.bad.url/contains+and/a space/in-path")
    rsp = test_client.get(f"/details/network.static.uri/{url}/")
    expected = {
        "api_error_message": "",
        "api_response": [{
            "classification": "TLP:CLEAR",
            "description": data["items"][0]["id"],
            "confirmed": False,
            "malicious": True,
            "data": data["items"][0],
        }],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_detailed_not_malicious(test_client, mock_lookup_success):
    """Test getting details for a valid tag that is found and is not malicious."""
    data = mock_lookup_success(
        items=[{
            "classification": "TLP:CLEAR",
            "id": "a" * 64,
            "result": {
                "score": 700,
            },
        }]
    )

    url = ul.quote("https://a.bad.url/contains+and/a space/in-path")
    rsp = test_client.get(f"/details/network.static.uri/{url}/")
    expected = {
        "api_error_message": "",
        "api_response": [{
            "classification": "TLP:CLEAR",
            "description": data["items"][0]["id"],
            "confirmed": False,
            "malicious": False,
            "data": data["items"][0],
        }],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_detailed_hash_lookup(test_client, mocker, mock_lookup_success):
    """Test getting details for a valid hash that requires additional lookups."""
    # result of 2nd lookup for actual result
    r = {
        "api_error_message": "",
        "api_response": {
            "items": [{
                "classification": "TLP:CLEAR",
                "id": "a" * 64,
                "result": {
                    "score": 1000,
                },
            }],
            "offset": 0,
            "rows": 25,
            "total": 1,
        },
        "api_server_version": "4.4.0.0",
        "api_status_code": 200,
    }
    mock_lookup2 = mocker.MagicMock(spec=requests.Response)
    mock_lookup2.status_code = 200
    mock_lookup2.json.return_value = r

    data = mock_lookup_success(
        # file index results do not have a result/score
        items=[{
            "classification": "TLP:CLEAR",
            "id": "a" * 64,
            "sha256": "a" * 64,
        }],
        side_effect=[mocker.DEFAULT, mock_lookup2],
    )
    assert "result" not in data["items"][0]

    rsp = test_client.get(f"/details/md5/{'a' * 32}/")
    expected = {
        "api_error_message": "",
        "api_response": [{
            "classification": "TLP:CLEAR",
            "description": r["api_response"]["items"][0]["id"],
            "confirmed": False,
            "malicious": True,
            "data": r["api_response"]["items"][0],
        }],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected
