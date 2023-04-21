from urllib import parse as ul

import pytest
import requests

from .app import app, TAG_MAPPING


@pytest.fixture()
def test_client():
    """generate a test client."""
    with app.test_client() as client:
        with app.app_context():
            app.config["TESTING"] = True
            yield client


def test_get_tags(test_client):
    """Ensure valid tag names are returned."""
    rsp = test_client.get("/tags/")
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == sorted(TAG_MAPPING)


def test_tag_found(test_client, mocker):
    """Validate respone for various tags that exists."""
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200

    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    # hash
    digest = "a" * 64
    rsp = test_client.get(f"/search/sha1/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search?query={digest}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # ip ioc
    ip_address = "127.0.0.1"
    rsp = test_client.get(f"/search/network.dynamic.ip/{ip_address}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search?query={ip_address}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # url ioc - quoted
    url = "https://a.bad.url/contains+and/a space/in-path"
    quoted = ul.quote(url)
    rsp = test_client.get(f"/search/network.dynamic.uri/{quoted}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search?query={quoted}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # domain ioc
    domain = "bad.domain"
    rsp = test_client.get(f"/search/network.static.domain/{domain}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search?query={domain}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_tag_dne(test_client, mocker):
    """Validate respone for various tags that do not exists."""
    digest = "a" * 32
    mock_response = mocker.MagicMock()
    mock_response.status_code = 404

    # setup mock response for a valid hash lookup
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/search/md5/{digest}/")
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

    rsp = test_client.get(f"/search/md5/{'a' * 32}/")
    expected = {
        "api_error_message": "Error submitting data to upstream.",
        "api_response": "Some bad response",
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid hash
    rsp = test_client.get("/search/sha1/abc/")
    expected = {
        "api_error_message": "Invalid hash provided. Require md5, sha1 or sha256",
        "api_response": None,
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/search/abc/abc/")
    assert rsp.status_code == 400
    assert rsp.json["api_error_message"].startswith("Invalid tag name: ")
