import base64

import pytest

import assemblyline_ui.helper.oauth as oauth_helper
from assemblyline.odm.models.config import OAuthProvider
from assemblyline_ui.helper.oauth import _host_matches, fetch_avatar


@pytest.fixture()
def provider_config():
    return OAuthProvider({
        "api_base_url": "https://graph.example.com/v1/",
        "avatar_allowed_hosts": ["avatars.example.com", "*.googleusercontent.com"],
    })


class FakeOAuthSession:
    def __init__(self, content_type="image/png", content=b"img-bytes"):
        self.calls = []
        self.content_type = content_type
        self.content = content

    def get(self, path):
        self.calls.append(path)
        session = self

        class Resp:
            ok = True
            headers = {"content-type": session.content_type}
            content = session.content

        return Resp()


class FakeResponse:
    def __init__(self, content_type="image/png", content=b"img-bytes", ok=True):
        self.ok = ok
        self.headers = {"content-type": content_type}
        self._body = content

        response = self

        class Raw:
            @staticmethod
            def read(amt, decode_content=True):
                return response._body[:amt]

        self.raw = Raw()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


@pytest.fixture()
def fake_network(monkeypatch):
    """Stub out the network so tests don't need DNS or outbound access."""
    requested = []

    def fake_get(url, **kwargs):
        requested.append((url, kwargs))
        return FakeResponse()

    monkeypatch.setattr(oauth_helper.requests, "get", fake_get)
    return requested


# --- SSRF targets must be rejected before any request is made ---

@pytest.mark.parametrize("url", [
    "http://127.0.0.1:9200/user/_search",
    "https://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "https://elastic:devpass@elasticsearch:9200/user/_search",
    "http://localhost:9000/bucket",
    "https://attacker.example.org/x.png",
    "file:///etc/passwd",
    "not a url",
])
def test_fetch_avatar_rejects_disallowed_urls(url, provider_config, fake_network):
    assert fetch_avatar(url, None, provider_config) is None
    assert fake_network == []


def test_fetch_avatar_rejects_api_base_url_prefix_confusion(provider_config, fake_network):
    session = FakeOAuthSession()
    assert fetch_avatar("https://graph.example.com.evil.io/v1/pic", session, provider_config) is None
    assert session.calls == []
    assert fake_network == []


# --- legitimate avatar sources still work ---

def test_fetch_avatar_uses_oauth_session_for_provider_hosted(provider_config):
    session = FakeOAuthSession()
    avatar = fetch_avatar("https://graph.example.com/v1/me/photo", session, provider_config)
    assert session.calls == ["me/photo"]
    assert avatar == "data:image/png;base64," + base64.b64encode(b"img-bytes").decode()


def test_fetch_avatar_allows_allowlisted_host(provider_config, fake_network):
    avatar = fetch_avatar("https://lh3.googleusercontent.com/a/photo", None, provider_config)
    assert avatar == "data:image/png;base64," + base64.b64encode(b"img-bytes").decode()
    url, kwargs = fake_network[0]
    assert kwargs.get("allow_redirects") is False
    assert kwargs.get("timeout") == 5


def test_fetch_avatar_allows_gravatar_when_enabled(provider_config, fake_network, monkeypatch):
    monkeypatch.setattr(oauth_helper.config.auth.oauth, "gravatar_enabled", True)
    assert fetch_avatar("https://www.gravatar.com/avatar/abc?s=256", None, provider_config) is not None

    monkeypatch.setattr(oauth_helper.config.auth.oauth, "gravatar_enabled", False)
    assert fetch_avatar("https://www.gravatar.com/avatar/abc?s=256", None, provider_config) is None


# --- response validation ---

def test_fetch_avatar_rejects_non_image_content(provider_config, fake_network, monkeypatch):
    monkeypatch.setattr(oauth_helper.requests, "get",
                        lambda url, **kw: FakeResponse(content_type="text/plain"))
    assert fetch_avatar("https://avatars.example.com/x", None, provider_config) is None


def test_fetch_avatar_rejects_oversized_content(provider_config, fake_network, monkeypatch):
    big = b"A" * (oauth_helper.MAX_AVATAR_SIZE + 1)
    monkeypatch.setattr(oauth_helper.requests, "get",
                        lambda url, **kw: FakeResponse(content=big))
    assert fetch_avatar("https://avatars.example.com/x", None, provider_config) is None


# --- helper units ---

@pytest.mark.parametrize("hostname,allowed,expected", [
    ("avatars.example.com", "avatars.example.com", True),
    ("lh3.googleusercontent.com", "*.googleusercontent.com", True),
    ("googleusercontent.com", "*.googleusercontent.com", True),
    ("evilgoogleusercontent.com", "*.googleusercontent.com", False),
    ("avatars.example.com.evil.io", "avatars.example.com", False),
    ("AVATARS.EXAMPLE.COM".lower(), "Avatars.Example.Com", True),
])
def test_host_matches(hostname, allowed, expected):
    assert _host_matches(hostname, allowed) is expected
