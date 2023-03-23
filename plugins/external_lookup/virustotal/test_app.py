import pytest
import requests

from .app import app, VALID_IOC


@pytest.fixture()
def test_client():
    """generate a test client."""
    with app.test_client() as client:
        with app.app_context():
            yield client


def test_get_valid_iocs(test_client):
    """Ensure iocs are returned."""
    rsp = test_client.get("/ioc/")

    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == VALID_IOC


def test_ioc_found(test_client, mocker):
    """Validate respone for various iocs that exists."""
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200

    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    # hash ioc
    digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    rsp = test_client.get(f"/ioc/hash/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "vt-hash": {
                "classification": "UNRESTRICTED",
                "link": f"https://www.virustotal.com/gui/search/{digest}/summary",
            },
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # ip ioc
    ip_address = "127.0.0.1"
    rsp = test_client.get(f"/ioc/ip-address/{ip_address}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "vt-ip-address": {
                "classification": "UNRESTRICTED",
                "link": f"https://www.virustotal.com/gui/ip-address/{ip_address}/summary",
            },
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_ioc_dne(test_client, mocker):
    """Validate respone for various iocs that do not exists."""
    digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    mock_response = mocker.MagicMock()
    mock_response.status_code = 404

    # setup mock response for a valid hash lookup
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/ioc/hash/{digest}/")
    expected = {
        "api_error_message": "No results.",
        "api_response": None,
        "api_status_code": 404,
    }
    assert rsp.status_code == 404
    assert rsp.json == expected


def test_error_conditions(test_client, mocker):
    """Validate error handling."""

    # unknown error
    mock_response = mocker.MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Some bad response"
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/ioc/hash/{'a' * 32}/")
    expected = {
        "api_error_message": "Error submitting data to upstream.",
        "api_response": "Some bad response",
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid hash
    rsp = test_client.get("/ioc/hash/abc}/")
    expected = {
        "api_error_message": "Invalid hash provided. Require md5, sha1 or sha256",
        "api_response": None,
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/ioc/abc/abc}/")
    assert rsp.status_code == 400
    assert rsp.json["api_error_message"].startswith("Invalid indicator name: ")
