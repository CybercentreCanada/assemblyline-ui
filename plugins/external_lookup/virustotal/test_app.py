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
def mock_lookup_exists(mocker):
    """Mock response for a generic lookup that exists."""

    def _mock_lookup_exists(
        *,
        last_analysis_stats={
            "confirmed-timeout": 0,
            "failure": 0,
            "harmless": 0,
            "malicious": 3,
            "suspicious": 0,
            "timeout": 0,
            "type-unsupported": 0,
            "undetected": 2,
        },
        sandboxes=None,
        threat_classifications=None,
    ):
        # create the default result
        r = {
            "data": {
                "attributes": {
                    "last_analysis_stats": last_analysis_stats,
                },
            },
        }
        if sandboxes:
            r["data"]["attributes"]["sandbox_verdicts"] = sandboxes
        if threat_classifications:
            r["data"]["attributes"]["popular_threat_classification"] = threat_classifications

        mock_response = mocker.MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = r

        # setup mock response for a valid hash lookup
        mock_session = mocker.patch.object(requests, "Session", autospec=True)
        mock_session.return_value.get.return_value = mock_response
        return r["data"]

    return _mock_lookup_exists


def test_get_tags(test_client):
    """Ensure valid tag names are returned."""
    rsp = test_client.get("/tags/")
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == {tname: server.CLASSIFICATION for tname in sorted(server.TAG_MAPPING)}


def test_tag_found(test_client, mock_lookup_exists):
    """Validate respone for various tags that exists."""
    mock_lookup_exists()
    # hash
    digest = "a" * 64
    rsp = test_client.get(f"/search/sha1/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search/{digest}",
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
            "link": f"https://www.virustotal.com/gui/search/{ip_address}",
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
    rsp_encoded_tag = ul.quote(ul.quote(url, safe=""), safe="")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "TLP:CLEAR",
            "link": f"https://www.virustotal.com/gui/search/{rsp_encoded_tag}",
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
            "link": f"https://www.virustotal.com/gui/search/{domain}",
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
        "api_status_code": 422,
    }
    assert rsp.status_code == 422
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/search/abc/abc/")
    assert rsp.status_code == 422
    assert rsp.json["api_error_message"].startswith("Invalid tag name: ")


def test_detailed_malicious(test_client, mock_lookup_exists):
    """Test getting details for a valid tag that is found and is malicious."""
    sandboxes = {
        "VMRay": {
            "category": "malicious",
            "sandbox_name": "VMRay",
            "malware_classification": ["MALWARE"],
        },
        "Yomi Hunter": {
            "category": "harmless",
            "sandbox_name": "Yomi Hunter",
            "malware_classification": ["CLEAN"],
        },
    }
    threat_classifications = {
        "suggested_threat_label": "trojan.w97m/rtfobfustream",
        "popular_threat_category": [{"count": 15, "value": "trojan"}],
        "popular_threat_name": [
            {"count": 3, "value": "w97m"},
            {"count": 2, "value": "rtfobfustream"},
            {"count": 2, "value": "pfkno"},
        ],
    }
    data = mock_lookup_exists(sandboxes=sandboxes, threat_classifications=threat_classifications)

    rsp = test_client.get(f"/details/sha256/{'a' * 64}/")
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "description": (
                    "3 security vendors and 1 sandboxes flagged this as malicious. Threat label: "
                    "trojan.w97m/rtfobfustream. Threat categories: trojan. Family labels: w97m, rtfobfustream, pfkno."
                ),
                "confirmed": False,
                "malicious": True,
                "data": data,
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_detailed_not_malicious(test_client, mock_lookup_exists):
    """Test getting details for a valid tag that is found and is not malicious."""
    data = mock_lookup_exists(
        last_analysis_stats={
            "confirmed-timeout": 0,
            "failure": 1,
            "harmless": 5,
            "malicious": 0,
            "suspicious": 1,
            "timeout": 0,
            "type-unsupported": 0,
            "undetected": 2,
        }
    )

    rsp = test_client.get(f"/details/sha256/{'a' * 64}/")
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "description": "0 security vendors flagged this as malicious.",
                "confirmed": False,
                "malicious": False,
                "data": data,
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected
