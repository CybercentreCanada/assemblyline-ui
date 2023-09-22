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
        additional_attrs=None,
    ):
        # create the default result
        r = {
            "data": {
                "attributes": {
                    "last_analysis_stats": last_analysis_stats,
                },
            },
        }
        if additional_attrs:
            for k, v in additional_attrs.items():
                r["data"]["attributes"][k] = v

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
    rsp = test_client.get(f"/details/sha1/{digest}/", query_string={"nodata": True})
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "link": f"https://www.virustotal.com/gui/search/{digest}",
                "count": 1,
                "confirmed": False,
                "malicious": True,
                "description": "3 security vendors and 0 sandboxes flagged this as malicious.",
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # ip ioc
    ip_address = "127.0.0.1"
    rsp = test_client.get(f"/details/network.dynamic.ip/{ip_address}/", query_string={"nodata": True})
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "link": f"https://www.virustotal.com/gui/search/{ip_address}",
                "count": 1,
                "confirmed": False,
                "malicious": True,
                "description": "3 security vendors flagged this as malicious.",
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # url ioc - quoted
    url = "https://a.bad.url/contains+and/a space/in-path"
    quoted = ul.quote(url)
    rsp = test_client.get(f"/details/network.dynamic.uri/{quoted}/", query_string={"nodata": True})
    rsp_encoded_tag = ul.quote(ul.quote(url, safe=""), safe="")
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "link": f"https://www.virustotal.com/gui/search/{rsp_encoded_tag}",
                "count": 1,
                "confirmed": False,
                "malicious": True,
                "description": "3 security vendors flagged this as malicious.",
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected

    # domain ioc
    domain = "bad.domain"
    rsp = test_client.get(f"/details/network.static.domain/{domain}/", query_string={"nodata": True})
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "link": f"https://www.virustotal.com/gui/search/{domain}",
                "count": 1,
                "confirmed": False,
                "malicious": True,
                "description": "3 security vendors flagged this as malicious.",
            }
        ],
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

    rsp = test_client.get(f"/details/md5/{digest}/", query_string={"nodata": True})
    expected = {
        "api_error_message": "No results.",
        "api_response": None,
        "api_status_code": 200,
    }
    assert rsp.status_code == 200
    assert rsp.json == expected


def test_error_conditions(test_client, mocker):
    """Validate error handling."""

    # unknown error
    mock_response = mocker.MagicMock()
    mock_response.status_code = 400
    mock_response.text = "Some bad response"
    mock_session = mocker.patch.object(requests, "Session", autospec=True)
    mock_session.return_value.get.return_value = mock_response

    rsp = test_client.get(f"/details/md5/{'a' * 32}/", query_string={"nodata": True})
    expected = {
        "api_error_message": "Error submitting data to upstream.",
        "api_response": "Some bad response",
        "api_status_code": 400,
    }
    assert rsp.status_code == 400
    assert rsp.json == expected

    # invalid hash
    rsp = test_client.get("/details/sha1/abc/", query_string={"nodata": True})
    expected = {
        "api_error_message": "Invalid hash provided. Require md5, sha1 or sha256",
        "api_response": None,
        "api_status_code": 422,
    }
    assert rsp.status_code == 422
    assert rsp.json == expected

    # invalid indicator name
    rsp = test_client.get("/details/abc/abc/", query_string={"nodata": True})
    assert rsp.status_code == 422
    assert rsp.json["api_error_message"].startswith("Invalid tag name: ")


def test_detailed_malicious(test_client, mock_lookup_exists):
    """Test getting details for a valid tag that is found and is malicious."""
    additional_attrs = {
        "sandbox_verdicts": {
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
        },
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.w97m/rtfobfustream",
            "popular_threat_category": [{"count": 15, "value": "trojan"}],
            "popular_threat_name": [
                {"count": 3, "value": "w97m"},
                {"count": 2, "value": "rtfobfustream"},
                {"count": 2, "value": "pfkno"},
            ],
        },
    }
    mock_lookup_exists(additional_attrs=additional_attrs)

    rsp = test_client.get(f"/details/sha256/{'a' * 64}/")
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "count": 1,
                "link": f"https://www.virustotal.com/gui/search/{'a' * 64}",
                "confirmed": False,
                "malicious": True,
                "description": (
                    "3 security vendors and 1 sandboxes flagged this as malicious. It was identified as "
                    "trojan.w97m/rtfobfustream. It was categorised with the labels trojan. It was given "
                    "the names w97m, rtfobfustream, pfkno."
                ),
                "enrichment": [
                    {
                        "group": "summary",
                        "name": "av_malicious",
                        "name_description": "",
                        "value": 3,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "sandbox_malicious",
                        "name_description": "",
                        "value": 1,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat",
                        "name_description": "",
                        "value": "trojan.w97m/rtfobfustream",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_family",
                        "name_description": "",
                        "value": "w97m",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_family",
                        "name_description": "",
                        "value": "rtfobfustream",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_family",
                        "name_description": "",
                        "value": "pfkno",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_category",
                        "name_description": "",
                        "value": "trojan",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "reputation",
                        "name_description": "",
                        "value": 0,
                        "value_description": "",
                    },
                    {
                        "group": "sandboxes",
                        "name": "VMRay",
                        "name_description": "",
                        "value": "malicious",
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_detailed_not_malicious(test_client, mock_lookup_exists):
    """Test getting details for a valid tag that is found and is not malicious."""
    mock_lookup_exists(
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
                "link": f"https://www.virustotal.com/gui/search/{'a' * 64}",
                "count": 1,
                "confirmed": False,
                "malicious": False,
                "description": "0 security vendors and 0 sandboxes flagged this as malicious.",
                "enrichment": [
                    {
                        "group": "summary",
                        "name": "av_malicious",
                        "name_description": "",
                        "value": 0,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "av_suspicious",
                        "name_description": "",
                        "value": 1,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "sandbox_malicious",
                        "name_description": "",
                        "value": 0,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "reputation",
                        "name_description": "",
                        "value": 0,
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected


def test_detailed_enrich(test_client, mock_lookup_exists):
    """Test getting enrichment details for a valid tag."""
    additional_attrs = {
        "sandbox_verdicts": {
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
        },
        "popular_threat_classification": {
            "suggested_threat_label": "trojan.w97m/rtfobfustream",
            "popular_threat_category": [{"count": 15, "value": "trojan"}],
            "popular_threat_name": [
                {"count": 3, "value": "w97m"},
                {"count": 2, "value": "pfkno"},
            ],
        },
        "sigma_analysis_results": [
            {
                "rule_title": "Change PowerShell Policies",
                "rule_source": "Sigma Rule Set (GitHub)",
                "rule_level": "medium",
                "rule_id": "06b79f9770d38bdf927774a9b99884df779bd40588c5ba0e70911df20927ce1",
                "rule_author": "Example_author",
                "rule_description": "Detects setting insecure policies",
            }
        ],
        "reputation": -83,
        "sigma_analysis_stats": {"high": 0, "medium": 1, "critical": 0, "low": 2},
        "crowdsourced_yara_results": [
            {
                "description": "Detects an embedded VBA project.",
                "source": "https://github.com/examples/yara-rules",
                "author": "Example",
                "ruleset_name": "Doc_with_VBA",
                "rule_name": "Doc_with_VBA",
                "ruleset_id": "0123456789",
            },
        ],
        "tags": ["docx", "cve-2019-0199", "cve-2023-36884"],
    }
    mock_lookup_exists(additional_attrs=additional_attrs)

    rsp = test_client.get(f"/details/sha256/{'a' * 64}/")
    expected = {
        "api_error_message": "",
        "api_response": [
            {
                "classification": "TLP:CLEAR",
                "link": f"https://www.virustotal.com/gui/search/{'a' * 64}",
                "count": 1,
                "description": (
                    "3 security vendors and 1 sandboxes flagged this as malicious. It was identified as "
                    "trojan.w97m/rtfobfustream. It was categorised with the labels trojan. It was given "
                    "the names w97m, pfkno."
                ),
                "confirmed": False,
                "malicious": True,
                "enrichment": [
                    {
                        "group": "summary",
                        "name": "av_malicious",
                        "name_description": "",
                        "value": 3,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "sandbox_malicious",
                        "name_description": "",
                        "value": 1,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat",
                        "name_description": "",
                        "value": "trojan.w97m/rtfobfustream",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_family",
                        "name_description": "",
                        "value": "w97m",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_family",
                        "name_description": "",
                        "value": "pfkno",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "threat_category",
                        "name_description": "",
                        "value": "trojan",
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "reputation",
                        "name_description": "",
                        "value": -83,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "sigma_alerts_medium",
                        "name_description": "",
                        "value": 1,
                        "value_description": "",
                    },
                    {
                        "group": "summary",
                        "name": "sigma_alerts_low",
                        "name_description": "",
                        "value": 2,
                        "value_description": "",
                    },
                    {
                        "group": "yara_hits",
                        "name": "https://github.com/examples/yara-rules",
                        "name_description": "",
                        "value": "Doc_with_VBA",
                        "value_description": "Detects an embedded VBA project.",
                    },
                    {
                        "group": "sigma_alerts",
                        "name": "medium",
                        "name_description": "",
                        "value": "Change PowerShell Policies [Example_author]",
                        "value_description": "",
                    },
                    {
                        "group": "info",
                        "name": "labels",
                        "name_description": "",
                        "value": "docx",
                        "value_description": "",
                    },
                    {
                        "group": "info",
                        "name": "labels",
                        "name_description": "",
                        "value": "cve-2019-0199",
                        "value_description": "",
                    },
                    {
                        "group": "info",
                        "name": "labels",
                        "name_description": "",
                        "value": "cve-2023-36884",
                        "value_description": "",
                    },
                    {
                        "group": "sandboxes",
                        "name": "VMRay",
                        "name_description": "",
                        "value": "malicious",
                        "value_description": "",
                    },
                ],
            }
        ],
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected
