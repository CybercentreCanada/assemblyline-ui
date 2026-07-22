import pytest
from requests.structures import CaseInsensitiveDict

from assemblyline_ui.api.v4 import proxy
from assemblyline_ui.app import app
from assemblyline_ui.config import config

from assemblyline.odm.models.config import APIProxies
from assemblyline.odm.random_data import create_users, wipe_users

# The proxy blueprint is only registered at startup when api_proxies is configured,
# add it here so the endpoint can be tested with the proxy_config fixture
if "proxy" not in app.blueprints:
    app.register_blueprint(proxy.proxy_api)

BASE_URL = "https://upstream.example.com/api/"


def test_get_proxied_url_valid_paths():
    assert proxy.get_proxied_url(BASE_URL, "endpoint") == "https://upstream.example.com/api/endpoint"
    assert proxy.get_proxied_url(BASE_URL, "sub/endpoint") == "https://upstream.example.com/api/sub/endpoint"

    # Dot segments that stay under the base path are normalized and allowed
    assert proxy.get_proxied_url(BASE_URL, "a/b/../c") == "https://upstream.example.com/api/a/c"

    # Base URL without a trailing slash resolves relative to its parent directory
    assert proxy.get_proxied_url("https://upstream.example.com/api", "endpoint") == \
        "https://upstream.example.com/endpoint"


def test_get_proxied_url_cannot_change_host():
    # Absolute URLs would completely replace the base with urljoin
    assert proxy.get_proxied_url(BASE_URL, "http://169.254.169.254/latest") is None
    assert proxy.get_proxied_url(BASE_URL, "https://evil.example.com/x") is None

    # Scheme-relative URLs keep the scheme but replace the host
    assert proxy.get_proxied_url(BASE_URL, "//169.254.169.254/latest") is None

    # Same host but different scheme
    assert proxy.get_proxied_url(BASE_URL, "http://upstream.example.com/api/endpoint") is None


def test_get_proxied_url_cannot_escape_path():
    # Rooted paths escape the base path prefix
    assert proxy.get_proxied_url(BASE_URL, "/other") is None

    # Dot segments may not climb out of the base path
    assert proxy.get_proxied_url(BASE_URL, "../secret") is None
    assert proxy.get_proxied_url(BASE_URL, "../../secret") is None
    assert proxy.get_proxied_url(BASE_URL, "sub/../../secret") is None

    # '../api-private/x' resolves to '/api-private/x', which shares the string prefix
    # '/api' with the base but is a different path segment, so it must be rejected
    assert proxy.get_proxied_url(BASE_URL, "../api-private/x") is None


@pytest.fixture(scope="module")
def datastore(datastore_connection):
    """Setup users."""
    try:
        create_users(datastore_connection)
        yield datastore_connection
    finally:
        wipe_users(datastore_connection)


@pytest.fixture()
def proxy_config():
    """Add a proxied server to the test configuration."""
    original_proxies = config.ui.api_proxies
    config.ui.api_proxies = {
        "upstream": APIProxies({
            "url": BASE_URL,
            "headers": [{"name": "x-forwarded-for-test", "value": "assemblyline"}],
        })
    }
    yield
    config.ui.api_proxies = original_proxies


@pytest.fixture()
def test_client(proxy_config):
    app.config["TESTING"] = True
    with app.test_client() as client:
        with app.app_context():
            yield client


@pytest.fixture()
def user_login_session(datastore, test_client):
    """Setup a login session for the test_client."""
    r = test_client.post("/api/v4/auth/login/", data={"user": "user", "password": "user"})
    for name, value in r.headers:
        if name == "Set-Cookie" and "XSRF-TOKEN" in value:
            # in form: ("Set-Cookie", "XSRF-TOKEN=<token>; Path=/")
            token = value.split(";")[0].split("=")[1]
            test_client.environ_base["HTTP_X_XSRF_TOKEN"] = token
    data = r.json["api_response"]
    yield data, test_client


class RecordingResponse:
    status_code = 200
    content = b"upstream content"
    headers = CaseInsensitiveDict()


@pytest.fixture()
def outbound_requests(monkeypatch):
    """Capture outbound requests issued by the proxy instead of sending them."""
    calls = []

    def fake_request(method, url, **kwargs):
        calls.append({"method": method, "url": url, **kwargs})
        return RecordingResponse()

    monkeypatch.setattr(proxy.requests, "request", fake_request)
    return calls


def test_proxy_forwards_relative_path(user_login_session, outbound_requests):
    _, client = user_login_session

    resp = client.get("/api/v4/proxy/upstream/endpoint/?filter=va%26lue&tag=a&tag=b")
    assert resp.status_code == 200
    assert resp.data == b"upstream content"

    assert len(outbound_requests) == 1
    call = outbound_requests[0]
    assert call["url"] == "https://upstream.example.com/api/endpoint/"
    # Params are passed for requests to encode, not concatenated into the URL,
    # and repeated keys are preserved
    assert call["params"]["filter"] == ["va&lue"]
    assert call["params"]["tag"] == ["a", "b"]
    assert call["allow_redirects"] is False
    assert call["headers"]["x-forwarded-for-test"] == "assemblyline"


def test_proxy_blocks_absolute_url_in_path(user_login_session, outbound_requests):
    _, client = user_login_session

    for path in [
        "/api/v4/proxy/upstream/http://169.254.169.254/latest",
        "/api/v4/proxy/upstream/http:%2F%2F169.254.169.254%2Flatest",
        "/api/v4/proxy/upstream/https://evil.example.com/x",
    ]:
        resp = client.get(path)
        assert resp.status_code == 400, path
    assert outbound_requests == []


def test_proxy_blocks_path_escape(user_login_session, outbound_requests):
    _, client = user_login_session

    resp = client.get("/api/v4/proxy/upstream/..%2F..%2Fsecret")
    assert resp.status_code == 400
    assert outbound_requests == []


def test_proxy_unknown_server(user_login_session, outbound_requests):
    _, client = user_login_session

    resp = client.get("/api/v4/proxy/unknown/endpoint")
    assert resp.status_code == 404
    assert outbound_requests == []


def test_proxy_passes_redirects_to_client(user_login_session, outbound_requests, monkeypatch):
    _, client = user_login_session

    class RedirectResponse(RecordingResponse):
        status_code = 302
        content = b""
        # Real servers send 'Location'; the proxy must match it case-insensitively
        headers = CaseInsensitiveDict({"Location": "https://upstream.example.com/api/moved"})

    monkeypatch.setattr(proxy.requests, "request",
                        lambda method, url, **kwargs: RedirectResponse())

    resp = client.get("/api/v4/proxy/upstream/endpoint")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "https://upstream.example.com/api/moved"
