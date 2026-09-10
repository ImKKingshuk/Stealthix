from __future__ import annotations

from types import SimpleNamespace

import requests

from stealthix.core.auth import ensure_authenticated, inject_csrf_tokens, requests_auth_for_session
from stealthix.core.session import ScanSession, SessionConfig


class _Response:
    def __init__(
        self,
        status_code: int,
        text: str,
        headers: dict[str, str] | None = None,
        payload: dict[str, object] | None = None,
    ):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "text/html"}
        self._payload = payload
        self.cookies = requests.cookies.RequestsCookieJar()

    def json(self):
        if self._payload is None:
            raise ValueError("no json")
        return self._payload


def test_bearer_auth_refreshes_token_and_updates_session(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="bearer",
            auth_config={
                "refresh_url": "/auth/refresh",
                "refresh_method": "POST",
                "refresh_body": {"refresh": "r1"},
            },
        )
    )
    calls: list[tuple[str, str]] = []

    class FakeClient:
        def __init__(self):
            self.cookies = requests.cookies.RequestsCookieJar()

        def request(self, method, url, **kwargs):
            calls.append((method, url))
            return _Response(
                200, "ok", {"Content-Type": "application/json"}, {"access_token": "new-token"}
            )

    monkeypatch.setattr("stealthix.core.auth.get_requests_client", lambda _session: FakeClient())

    refreshed = ensure_authenticated(session, force=True, reason="test")

    assert refreshed is True
    assert calls == [("POST", "http://example.com/auth/refresh")]
    assert session.config.auth_token == "new-token"
    assert session.config.auth_config["token"] == "new-token"
    assert session.creds.get("auth_token") == "new-token"
    assert session.metadata["auth"]["authenticated"] is True


def test_form_auth_detects_hidden_csrf_and_persists_cookies(monkeypatch):
    login_page = """
    <form method='post' action='/login'>
      <input type='hidden' name='csrf_token' value='abc123'>
      <input type='text' name='username'>
      <input type='password' name='password'>
    </form>
    """
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="form",
            auth_config={
                "login_url": "/signin",
                "username": "alice",
                "password": "s3cr3t",
                "success_indicator": "dashboard",
            },
        )
    )
    calls: list[tuple[str, str, dict[str, object] | None]] = []

    class FakeClient:
        def __init__(self):
            self.cookies = requests.cookies.RequestsCookieJar()

        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs.get("data")))
            if method == "GET":
                return _Response(200, login_page)
            self.cookies.set("sessionid", "cookie-1")
            return _Response(200, "dashboard")

    monkeypatch.setattr("stealthix.core.auth.get_requests_client", lambda _session: FakeClient())

    authenticated = ensure_authenticated(session, force=True, reason="test-form")

    assert authenticated is True
    assert calls[0][:2] == ("GET", "http://example.com/signin")
    assert calls[1][0] == "POST"
    assert calls[1][1] == "http://example.com/login"
    assert calls[1][2]["csrf_token"] == "abc123"
    assert calls[1][2]["username"] == "alice"
    assert session.config.cookies["sessionid"] == "cookie-1"
    assert session.metadata["auth"]["auth_type"] == "form"


def test_custom_auth_script_can_populate_headers_and_token(tmp_path):
    script = tmp_path / "auth_script.py"
    script.write_text(
        "def authenticate(session, context):\n"
        "    return {'headers': {'X-Auth': '1'}, 'cookies': {'sid': 'abc'}, 'auth_token': 'token-1', 'metadata': {'source': 'script'}}\n",
        encoding="utf-8",
    )
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com", auth_type="script", auth_config={"script": str(script)}
        )
    )

    authenticated = ensure_authenticated(session, force=True, reason="script")

    assert authenticated is True
    assert session.config.headers["X-Auth"] == "1"
    assert session.config.cookies["sid"] == "abc"
    assert session.config.auth_token == "token-1"
    assert session.metadata["auth"]["source"] == "script"


def test_basic_auth_returns_requests_adapter():
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="basic",
            auth_config={"username": "alice", "password": "pw"},
        )
    )

    adapter = requests_auth_for_session(session)

    assert adapter is not None
    assert adapter.__class__.__name__ == "HTTPBasicAuth"


def test_inject_csrf_tokens_fetches_tokens_for_post_requests(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="form",
            auth_config={"csrf_url": "/form", "csrf_field": "csrf_token"},
        )
    )

    class FakeClient:
        def __init__(self):
            self.cookies = requests.cookies.RequestsCookieJar()

        def request(self, method, url, **kwargs):
            return _Response(
                200,
                "<form action='/submit'><input type='hidden' name='csrf_token' value='xyz'></form>",
            )

    monkeypatch.setattr("stealthix.core.auth.get_requests_client", lambda _session: FakeClient())

    data = inject_csrf_tokens(session, "http://example.com/submit", {"name": "alice"})

    assert data["csrf_token"] == "xyz"
