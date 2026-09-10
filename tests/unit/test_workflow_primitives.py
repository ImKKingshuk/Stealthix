from __future__ import annotations

from types import SimpleNamespace

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.proxy.passive import passive_injection_hints
from stealthix.workflows import (
    RequestSpec,
    expand_payload_positions,
    find_payload_markers,
    import_curl,
    import_har,
    import_raw_http,
    replay_request,
)


def test_raw_http_import_normalizes_request_spec():
    spec = import_raw_http(
        "POST /login?next=/admin HTTP/1.1\r\n"
        "Host: example.test\r\n"
        "Cookie: sid=abc; theme=dark\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 19\r\n"
        "\r\n"
        "user=alice&id=42"
    )

    assert spec.method == "POST"
    assert spec.url == "http://example.test/login?next=/admin"
    assert spec.headers == {"Content-Type": "application/x-www-form-urlencoded"}
    assert spec.cookies == {"sid": "abc", "theme": "dark"}
    assert spec.data == {"user": "alice", "id": "42"}
    assert set(spec.target_params or []) == {"next", "user", "id"}


def test_curl_and_har_imports_normalize_body_and_query():
    curl_spec = import_curl(
        "curl -X PATCH -H 'Content-Type: application/json' "
        "-H 'X-Tenant: blue' --data-raw '{\"name\":\"alice\"}' "
        "https://api.example.test/users/1"
    )
    assert curl_spec.method == "PATCH"
    assert curl_spec.body_format == "json"
    assert curl_spec.data == {"name": "alice"}
    assert curl_spec.headers["X-Tenant"] == "blue"

    [har_spec] = import_har(
        {
            "log": {
                "entries": [
                    {
                        "request": {
                            "method": "GET",
                            "url": "https://example.test/search",
                            "queryString": [{"name": "q", "value": "test"}],
                            "headers": [{"name": "Accept", "value": "text/html"}],
                        }
                    }
                ]
            }
        }
    )
    assert har_spec.url == "https://example.test/search?q=test"
    assert har_spec.headers == {"Accept": "text/html"}
    assert har_spec.target_params == ["q"]


def test_repeater_replays_through_existing_http_path_and_restores_session(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="https://example.test/original",
            method="GET",
            headers={"X-Default": "yes"},
            cookies={"base": "1"},
        )
    )
    spec = RequestSpec(
        method="POST",
        url="https://example.test/replay",
        headers={"X-Replay": "1"},
        cookies={"sid": "abc"},
        data={"id": "42"},
        body_format="form",
    )
    captured: dict[str, object] = {}

    def fake_make_request(active_session, url, data=None, method=None, use_cache=True):
        captured["url"] = url
        captured["data"] = data
        captured["method"] = method
        captured["headers"] = dict(active_session.config.headers)
        captured["cookies"] = dict(active_session.config.cookies)
        captured["body_format"] = active_session.config.body_format
        captured["use_cache"] = use_cache
        return "ok", 0.01

    monkeypatch.setattr("stealthix.workflows.repeater.make_request", fake_make_request)

    result = replay_request(session, spec, use_cache=False)

    assert result.body == "ok"
    assert captured == {
        "url": "https://example.test/replay",
        "data": {"id": "42"},
        "method": "POST",
        "headers": {"X-Default": "yes", "X-Replay": "1"},
        "cookies": {"base": "1", "sid": "abc"},
        "body_format": "form",
        "use_cache": False,
    }
    assert session.config.method == "GET"
    assert session.config.headers == {"X-Default": "yes"}
    assert session.config.cookies == {"base": "1"}


def test_intruder_marker_expansion_replaces_url_headers_and_body():
    spec = RequestSpec(
        method="POST",
        url="https://example.test/search?q=§term§",
        headers={"X-Tenant": "{{tenant}}"},
        data={"filter": "name:§term§"},
    )

    markers = find_payload_markers(spec)
    expanded = expand_payload_positions(
        spec,
        {"term": ["alice", "bob"], "tenant": ["red"]},
        mode="clusterbomb",
    )

    assert {(marker.name, marker.location) for marker in markers} >= {
        ("term", "url"),
        ("term", "body"),
        ("tenant", "header"),
    }
    assert [item.url for item in expanded] == [
        "https://example.test/search?q=alice",
        "https://example.test/search?q=bob",
    ]
    assert expanded[0].headers["X-Tenant"] == "red"
    assert expanded[1].data == {"filter": "name:bob"}


def test_passive_injection_hints_score_captured_request_fields():
    spec = RequestSpec(
        method="POST",
        url="https://example.test/users/42?search=admin",
        headers={"X-Tenant": "blue", "Authorization": "secret"},
        data={"profile": {"id": "99"}, "name": "alice"},
    )

    hints = passive_injection_hints(spec)
    keys = {(hint.location, hint.name) for hint in hints}

    assert ("query", "search") in keys
    assert ("body", "profile.id") in keys
    assert ("path", "path[2]") in keys
    assert ("header", "Authorization") not in keys
