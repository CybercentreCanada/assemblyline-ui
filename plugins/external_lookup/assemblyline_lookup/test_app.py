import pytest
import requests

from .app import app, CLASSIFICATION, TAG_MAPPING, URL_BASE


@pytest.fixture()
def test_client():
    """generate a test client."""
    with app.test_client() as client:
        with app.app_context():
            app.config["TESTING"] = True
            yield client


def test_get_mappings(test_client, mocker):
    """Ensure tags are returned."""
    rsp = test_client.get("/tags/")
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == {tname: CLASSIFICATION for tname in sorted(TAG_MAPPING)}


def test_hash_found(test_client, mocker):
    """Validate respone for a hash that exists."""
    digest = "a" * 64
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "items": [{
                "classification": "TLP:CLEAR",
                "id": digest,
            }],
            "offset": 0,
            "rows": 1,
            "total": 1,
        },
        "api_server_version": "4.4.0.0",
        "api_status_code": 200,
    }

    # setup mock response for a valid hash lookup
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/search/sha256/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"{URL_BASE}/search/file?query={digest}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200, rsp.json["api_error_message"]
    assert rsp.json == expected


def test_hash_dne(test_client, mocker):
    """Validate respone for a hash that does not exists."""
    digest = "a" * 32
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "items": [],
            "offset": 0,
            "rows": 1,
            "total": 0,
        },
        "api_server_version": "4.4.0.0",
        "api_status_code": 200,
    }

    # setup mock response for a valid hash lookup
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/search/md5/{digest}/")
    expected = {
        "api_error_message": "No items found",
        "api_response": "",
        "api_status_code": 404,
    }
    assert rsp.status_code == 404
    assert rsp.json == expected


def test_error_conditions(test_client, mocker):
    """Validate error handling."""

    # unknown error
    mock_response = mocker.MagicMock()
    mock_response.status_code = 400
    mock_response.json.return_value = {
        "api_error_message": "Some bad response",
        "api_response": "",
        "api_server_version": "4.4.0.0",
        "api_status_code": 400,
    }
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/search/md5/{'a' * 32}/")
    expected = {
        "api_error_message": "Some bad response",
        "api_response": "",
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid hash
    rsp = test_client.get("/search/md5/abc}/")
    expected = {
        "api_error_message": "Invalid hash provided. Require md5, sha1 or sha256",
        "api_response": "",
        "api_status_code": 422,
    }
    assert rsp.status_code == 422
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/search/abc/abc}/")
    assert rsp.status_code == 422
    assert rsp.json["api_error_message"].startswith("Invalid tag name: ")
