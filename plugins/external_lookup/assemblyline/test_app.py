import pytest
import requests

from .app import app, TAG_MAPPING, URL_BASE


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
    assert data == TAG_MAPPING


def test_hash_found(test_client, mocker):
    """Validate respone for a hash that exists."""
    digest = "7de2c1bf58bce09eecc70476747d88a26163c3d6bb1d85235c24a558d1f16754"
    mock_response = mocker.MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "api_error_message": "",
        "api_response": {
            "items": [{
                "classification": "UNRESTRICTED",
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
    mock_session.return_value.post.return_value = mock_response

    rsp = test_client.get(f"/search/sha256/{digest}/")
    expected = {
        "api_error_message": "",
        "api_response": {
            "classification": "UNRESTRICTED",
            "link": f"{URL_BASE}/search/file?query={digest}",
            "count": 1,
        },
        "api_status_code": 200,
    }

    assert rsp.status_code == 200
    assert rsp.json == expected
