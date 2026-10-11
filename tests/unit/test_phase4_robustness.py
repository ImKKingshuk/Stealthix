from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from stealthix.core.history import RequestHistory
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.detection.websocket import _WebSocketClient
from stealthix.oob import HttpOASTProvider, provider_from_env
from stealthix.proxy.passive import passive_injection_hints
from stealthix.proxy.workspace import CapturedExchange, CapturedResponse, ProxyWorkspace
from stealthix.workflows import (
    RequestSpec,
    expand_payload_positions,
    find_payload_markers,
    replay_request,
)


def test_http_oast_provider_callbacks_and_polling():
    provider = HttpOASTProvider(
        endpoint_url="https://oast.example.test",
        poll_url="https://oast.example.test/api/events",
        auth_header="Bearer secret-token",
    )
    assert provider.domain == "oast.example.test"
    assert provider.host_for_token("tok123") == "tok123.oast.example.test"
    assert provider.callback_url_for_token("tok123") == "https://oast.example.test/tok123"

    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(
        [
            {
                "protocol": "http",
                "host": "tok123.oast.example.test",
                "url": "/tok123",
                "timestamp": 1700000000.0,
            }
        ]
    ).encode("utf-8")
    mock_resp.__enter__.return_value = mock_resp

    with patch("urllib.request.urlopen", return_value=mock_resp):
        confirmation = provider.wait_for_tokens(["tok123", "tok456"], timeout=0.1)

    assert confirmation.provider == "http-oast"
    assert confirmation.confirmed["tok123"] is True
    assert confirmation.confirmed["tok456"] is False
    assert len(confirmation.interactions) == 1
    assert confirmation.interactions[0].token == "tok123"


def test_provider_from_env_builds_http_oast(monkeypatch):
    monkeypatch.setenv("STEALTHIX_OOB_HTTP_URL", "https://custom.oast.org")
    monkeypatch.setenv("STEALTHIX_OOB_POLL_URL", "https://custom.oast.org/poll")
    monkeypatch.setenv("STEALTHIX_OOB_AUTH_HEADER", "ApiKey 999")
    monkeypatch.setenv("STEALTHIX_OOB_DOMAIN", "custom.oast.org")

    provider = provider_from_env()
    assert isinstance(provider, HttpOASTProvider)
    assert provider.endpoint_url == "https://custom.oast.org"
    assert provider.poll_url == "https://custom.oast.org/poll"
    assert provider.auth_header == "ApiKey 999"
    assert provider.domain == "custom.oast.org"


def test_passive_injection_hints_detects_cookies_and_raw_body():
    # Test JSON in raw_body
    spec_json = RequestSpec(
        method="POST",
        url="https://example.test/api/v1/auth",
        data=None,
        raw_body='{"username": "admin", "query": "SELECT 1 FROM users"}',
        cookies={"session_id": "42", "tracking": "123' OR 1=1--"},
    )
    hints_json = passive_injection_hints(spec_json)
    locations = {(h.location, h.name) for h in hints_json}
    assert ("body", "username") in locations or ("body", "query") in locations
    assert ("cookie", "session_id") in locations or ("cookie", "tracking") in locations

    # Test form-urlencoded in raw_body
    spec_form = RequestSpec(
        method="POST",
        url="https://example.test/search",
        data=None,
        raw_body="q=test&account_id=9876",
    )
    hints_form = passive_injection_hints(spec_form)
    locations_form = {(h.location, h.name) for h in hints_form}
    assert ("body", "q") in locations_form or ("body", "account_id") in locations_form


def test_har_export_preserves_duplicate_query_params(tmp_path):
    ws = ProxyWorkspace(tmp_path)
    spec = RequestSpec(
        method="GET",
        url="https://example.test/filter?tag=blue&tag=green&id=1",
    )
    ws.capture_exchange(
        spec,
        response=CapturedResponse(status_code=200, headers={}, body="ok", elapsed=0.05),
    )
    har_str = ws.export_payload(format="har")
    har_data = json.loads(har_str)
    query_entries = har_data["log"]["entries"][0]["request"]["queryString"]
    names = [param["name"] for param in query_entries]
    values = [param["value"] for param in query_entries]
    assert names.count("tag") == 2
    assert "blue" in values and "green" in values


def test_intruder_cookie_marker_expansion():
    spec = RequestSpec(
        method="GET",
        url="https://example.test/profile",
        cookies={"auth": "§token§", "track": "{{tracker}}"},
    )
    markers = find_payload_markers(spec)
    marker_locations = {(m.name, m.location) for m in markers}
    assert ("token", "cookie") in marker_locations
    assert ("tracker", "cookie") in marker_locations

    expanded = expand_payload_positions(
        spec,
        {"token": ["tokA", "tokB"], "tracker": ["tr1"]},
        mode="clusterbomb",
    )
    assert len(expanded) == 2
    assert expanded[0].cookies["auth"] == "tokA"
    assert expanded[0].cookies["track"] == "tr1"
    assert expanded[1].cookies["auth"] == "tokB"
    assert expanded[1].cookies["track"] == "tr1"


def test_history_latest_and_repeater_response_metadata(monkeypatch):
    history = RequestHistory()
    assert history.latest() is None
    history.add(
        url="https://example.test/api",
        method="GET",
        status="200",
        elapsed=0.04,
        metadata={"headers": {"Content-Type": "application/json", "X-Server": "prod"}},
    )
    latest = history.latest()
    assert latest is not None
    assert latest["url"] == "https://example.test/api"
    assert latest["status"] == "200"

    session = ScanSession(SessionConfig(base_url="https://example.test/api"))
    spec = RequestSpec(method="GET", url="https://example.test/api")

    def fake_make_request(active_session, url, data=None, method=None, use_cache=True):
        active_session.history.add(
            url=url,
            method=method or "GET",
            status="201",
            elapsed=0.03,
            metadata={"headers": {"X-Custom": "tested"}},
        )
        return '{"created": true}', 0.03

    monkeypatch.setattr("stealthix.workflows.repeater.make_request", fake_make_request)
    result = replay_request(session, spec)
    assert result.body == '{"created": true}'
    assert result.status_code == 201
    assert result.headers.get("X-Custom") == "tested"


def test_websocket_client_ip_address_host():
    client = _WebSocketClient("wss://127.0.0.1:8443", verify_tls=False)
    mock_sock = MagicMock()

    import base64
    import hashlib

    def fake_sendall(data):
        for line in data.decode("utf-8", errors="replace").splitlines():
            if line.lower().startswith("sec-websocket-key:"):
                key = line.split(":", 1)[1].strip()
                accept = base64.b64encode(
                    hashlib.sha1(f"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode("ascii")).digest()
                ).decode("ascii")
                mock_sock.recv.return_value = (
                    f"HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: {accept}\r\n\r\n".encode()
                )

    mock_sock.sendall.side_effect = fake_sendall

    with patch("socket.create_connection", return_value=mock_sock), patch(
        "ssl.create_default_context"
    ) as mock_ssl_ctx:
        ctx_instance = MagicMock()
        ctx_instance.wrap_socket.return_value = mock_sock
        mock_ssl_ctx.return_value = ctx_instance

        client.connect()

        # For an IP address, server_hostname should be None
        ctx_instance.wrap_socket.assert_called_once_with(mock_sock, server_hostname=None)
