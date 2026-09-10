from __future__ import annotations

import asyncio
from types import SimpleNamespace

import requests

from stealthix.core.http import async_make_request, make_request
from stealthix.core.session import ScanSession, SessionConfig


class _DummyResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def test_make_request_retries_rate_limits_and_records_hostile_metadata(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    calls: list[dict[str, str]] = []
    responses = iter(
        [
            _DummyResponse(429, "slow down", {"Retry-After": "0", "Content-Type": "text/plain"}),
            _DummyResponse(200, "ok", {"Content-Type": "text/plain"}),
        ]
    )

    def fake_get(url, *, headers, cookies, auth=None, proxies, timeout, verify):
        calls.append(dict(headers))
        return next(responses)

    monkeypatch.setenv("STEALTHIX_HTTP_RETRIES", "1")
    monkeypatch.setenv("STEALTHIX_HTTP_BACKOFF", "0")
    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(get=fake_get, post=None),
    )
    monkeypatch.setattr("stealthix.core.http.time.sleep", lambda _delay: None)

    body, _elapsed = make_request(session, "http://example.com")

    assert body == "ok"
    assert len(calls) == 2
    assert calls[1]["Cache-Control"] == "no-cache"
    assert session.history.entries[-1]["metadata"]["retried"] is True
    assert session.history.entries[-1]["metadata"]["attempts"][0]["status_code"] == 429
    assert session.metadata["hostile_target"]["rate_limited_responses"] == 1


def test_async_make_request_delegates_to_sync_request(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    monkeypatch.setattr(
        "stealthix.core.http.make_request",
        lambda *_args, **_kwargs: ("ok", 0.01),
    )

    body, elapsed = asyncio.run(async_make_request(session, "http://example.com"))

    assert body == "ok"
    assert elapsed == 0.01


def test_make_request_sends_multipart_payloads_for_discovered_file_upload_forms(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/upload",
            method="POST",
            body_format="form",
            data={"username": "alice", "avatar": "PAYLOAD"},
        ),
        metadata={"multipart_fields": ["avatar"]},
    )
    calls: dict[str, object] = {}

    def fake_post(url, *, headers, cookies, data, files, auth=None, proxies, timeout, verify):
        calls["url"] = url
        calls["data"] = data
        calls["files"] = files
        return _DummyResponse(200, "ok", {"Content-Type": "text/plain"})

    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(get=None, post=fake_post),
    )

    body, _elapsed = make_request(session, "http://example.com/upload", method="POST")

    assert body == "ok"
    assert calls["data"] == {"username": "alice"}
    assert calls["files"]["avatar"][1] == b"PAYLOAD"


def test_make_request_reauthenticates_once_after_401(monkeypatch):
    session = ScanSession(
        SessionConfig(base_url="http://example.com", auth_type="bearer", auth_token="old-token")
    )
    headers_seen: list[dict[str, str]] = []
    responses = iter(
        [
            _DummyResponse(401, "unauthorized", {"Content-Type": "text/plain"}),
            _DummyResponse(200, "ok", {"Content-Type": "text/plain"}),
        ]
    )

    def fake_get(url, *, headers, cookies, auth, proxies, timeout, verify):
        headers_seen.append(dict(headers))
        return next(responses)

    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(get=fake_get, post=None),
    )
    monkeypatch.setattr(
        "stealthix.core.http.prepare_request_auth",
        lambda _session, **kwargs: (
            {"Authorization": f"Bearer {_session.config.auth_token}"},
            kwargs["data"],
            None,
        ),
    )

    def fake_handle_auth_failure(_session, *, status_code, url):
        assert status_code == 401
        _session.config.auth_token = "new-token"
        return True

    monkeypatch.setattr("stealthix.core.http.handle_auth_failure", fake_handle_auth_failure)

    body, _elapsed = make_request(session, "http://example.com")

    assert body == "ok"
    assert headers_seen == [
        {"Authorization": "Bearer old-token"},
        {"Authorization": "Bearer new-token"},
    ]


def test_make_request_adaptively_retries_blocked_requests(monkeypatch):
    calls = []

    def fake_send(*_args, **kwargs):
        response = requests.Response()
        response.status_code = 403 if not calls else 200
        response._content = b"blocked" if not calls else b"ok"
        calls.append(kwargs)
        return response

    monkeypatch.setattr("stealthix.core.http._send_requests_request", fake_send)
    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})

    session = ScanSession(
        SessionConfig(
            base_url="http://example.test/api",
            method="POST",
            body_format="json",
            data={"payload": "1 UNION SELECT"},
            tamper_retry_budget=2,
        )
    )

    text, _elapsed = make_request(
        session, "http://example.test/api", method="POST", data=session.config.data
    )

    assert text == "ok"
    assert len(calls) >= 2
    assert calls[1]["data"]["payload"] != "1 UNION SELECT"
    assert session.metadata["adaptive_waf"]["applied"] is True
