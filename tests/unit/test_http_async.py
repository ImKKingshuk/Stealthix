from __future__ import annotations

import asyncio
import json
from typing import Any

from stealthix.core.http_async import make_async_request
from stealthix.core.session import ScanSession, SessionConfig


def test_async_rust_client_is_constructed_with_each_session_configuration(monkeypatch):
    constructed: list[dict[str, Any]] = []

    class FakeHttpClient:
        def __init__(self, *, proxy, timeout, verify_tls):
            constructed.append({"proxy": proxy, "timeout": timeout, "verify_tls": verify_tls})

        async def async_request(self, **_kwargs):
            return "ok"

    monkeypatch.setattr(
        "stealthix.utils.load_rust_core",
        lambda: {"HttpClient": FakeHttpClient},
    )

    first = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            proxy="http://proxy-one.local:8080",
            timeout=3.0,
            verify_tls=False,
        )
    )
    second = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            proxy="http://proxy-two.local:8080",
            timeout=9.0,
            verify_tls=True,
        )
    )

    assert asyncio.run(make_async_request(first, "http://example.com/one"))[0] == "ok"
    assert asyncio.run(make_async_request(second, "http://example.com/two"))[0] == "ok"

    assert constructed == [
        {
            "proxy": "http://proxy-one.local:8080",
            "timeout": 3.0,
            "verify_tls": False,
        },
        {
            "proxy": "http://proxy-two.local:8080",
            "timeout": 9.0,
            "verify_tls": True,
        },
    ]


def test_async_post_json_sends_encoded_body_headers_cookies_and_records_status(monkeypatch):
    calls: list[dict[str, Any]] = []

    class FakeHttpClient:
        def __init__(self, **_kwargs):
            pass

        async def async_request(self, **kwargs):
            calls.append(kwargs)
            return {
                "text": "created",
                "status_code": 201,
                "headers": {"Content-Type": "application/json"},
            }

    monkeypatch.setattr(
        "stealthix.utils.load_rust_core",
        lambda: {"HttpClient": FakeHttpClient},
    )

    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/items",
            method="POST",
            body_format="json",
            data={"name": "needle"},
            headers={"X-Test": "1"},
            cookies={"sid": "abc"},
            auth_type="bearer",
            auth_token="token-1",
        )
    )

    body, _elapsed = asyncio.run(make_async_request(session, "http://example.com/items"))

    assert body == "created"
    assert calls == [
        {
            "method": "POST",
            "url": "http://example.com/items",
            "headers": {
                "X-Test": "1",
                "Content-Type": "application/json",
                "Authorization": "Bearer token-1",
            },
            "cookies": {"sid": "abc"},
            "body": json.dumps({"name": "needle"}),
        }
    ]
    entry = session.history.entries[-1]
    assert entry["status"] == "201"
    assert entry["metadata"]["status_code"] == 201
    assert entry["metadata"]["transport"] == "rust-async"
    assert entry["metadata"]["request_body"] == json.dumps({"name": "needle"})


def test_async_put_with_body_uses_sync_fallback_because_rust_binding_drops_body(monkeypatch):
    calls: list[dict[str, Any]] = []

    class FakeHttpClient:
        def __init__(self, **_kwargs):
            raise AssertionError("Rust async client should not be used for PUT bodies")

    def fake_make_request(session, url, data=None, method=None, *, use_cache=True):
        calls.append(
            {
                "url": url,
                "data": data,
                "method": method,
                "use_cache": use_cache,
                "timeout": session.config.timeout,
            }
        )
        return "updated", 0.02

    monkeypatch.setattr(
        "stealthix.utils.load_rust_core",
        lambda: {"HttpClient": FakeHttpClient},
    )
    monkeypatch.setattr("stealthix.core.http.make_request", fake_make_request)

    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/items/1",
            method="PUT",
            body_format="json",
            data={"name": "replacement"},
            timeout=7.0,
        )
    )

    body, elapsed = asyncio.run(make_async_request(session, "http://example.com/items/1"))

    assert (body, elapsed) == ("updated", 0.02)
    assert calls == [
        {
            "url": "http://example.com/items/1",
            "data": {"name": "replacement"},
            "method": "PUT",
            "use_cache": True,
            "timeout": 7.0,
        }
    ]
