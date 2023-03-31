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


def test_get_mappings(test_client, mocker):
    """Ensure tags are returned."""
    rsp = test_client.get("/tags/")
    assert rsp.status_code == 200
    data = rsp.json["api_response"]
    assert data == TAG_MAPPING
