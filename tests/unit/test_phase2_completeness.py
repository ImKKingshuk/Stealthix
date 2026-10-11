"""
Unit and integration tests for phase 2 completeness and hardening.
"""

from __future__ import annotations

import base64
import hashlib
import json
import ssl
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

import stealthix.detection as det
import stealthix.evasion as ev
import stealthix.oob as oob
from stealthix._tui_callback_core import handle_core_action
from stealthix.config import load_config
from stealthix.core.http import _attempt_adaptive_retry
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.detection.graphql import _post_json
from stealthix.detection.websocket import _exchange_message, _WebSocketClient
from stealthix.evasion.adaptive import AdaptiveCandidate


def test_adaptive_retry_records_successful_history():
    """Verify that successful adaptive retries add an entry to session.history."""
    session = ScanSession(SessionConfig(base_url="http://test.local"))

    candidate = AdaptiveCandidate(
        name="adapted retry test",
        url="http://test.local/vuln?id=1",
        data=None,
        headers={"X-Test": "adapted"},
        body_format="form",
        transport="python",
    )

    fake_response = requests.Response()
    fake_response.status_code = 200
    fake_response._content = b"bypassed content"
    fake_response.headers["Content-Type"] = "text/html"

    with patch("stealthix.core.http.build_retry_candidates", return_value=[candidate]), \
         patch("stealthix.core.http._send_requests_request", return_value=fake_response), \
         patch("stealthix.core.http.record_adaptive_result"):
        result = _attempt_adaptive_retry(
            session,
            url="http://test.local/vuln?id=1",
            request_method="GET",
            headers={"Original": "header"},
            cookies={},
            data=None,
            body_format="form",
            multipart_fields=set(),
            auth=None,
            proxies=None,
            timeout=5.0,
            verify_tls=False,
            client=MagicMock(),
            use_cache=False,
        )

    assert result is not None
    text, elapsed = result
    assert text == "bypassed content"

    # Check history
    history = session.history.to_list()
    assert len(history) >= 1
    last = history[-1]
    assert last["url"] == "http://test.local/vuln?id=1"
    assert last["method"] == "GET"
    assert last["status"] == "200"
    assert last["metadata"]["adaptive_bypassed"] is True
    assert last["metadata"]["status_code"] == 200
    assert last["metadata"]["headers"]["Content-Type"] == "text/html"


def test_websocket_client_respects_verify_tls():
    """Verify _WebSocketClient disables SSL verification when verify_tls=False."""
    client_verified = _WebSocketClient("wss://example.test", verify_tls=True)
    assert client_verified.verify_tls is True

    client_unverified = _WebSocketClient("wss://example.test", verify_tls=False)
    assert client_unverified.verify_tls is False

    mock_sock = MagicMock()

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
    with patch("socket.create_connection", return_value=mock_sock), \
         patch("ssl.create_default_context") as mock_ssl_ctx:
        ctx_instance = MagicMock()
        ctx_instance.wrap_socket.return_value = mock_sock
        mock_ssl_ctx.return_value = ctx_instance

        client_unverified.connect()

        assert ctx_instance.check_hostname is False
        assert ctx_instance.verify_mode == ssl.CERT_NONE
        ctx_instance.wrap_socket.assert_called_once_with(mock_sock, server_hostname="example.test")


def test_websocket_exchange_passes_session_verify_tls():
    """Verify _exchange_message passes verify_tls from session config."""
    session = ScanSession(SessionConfig(base_url="wss://test.local", verify_tls=False))

    with patch("stealthix.detection.websocket._WebSocketClient") as mock_client_cls:
        client_mock = MagicMock()
        client_mock.__enter__.return_value = client_mock
        client_mock.read_message.return_value = "response msg"
        mock_client_cls.return_value = client_mock

        resp, elapsed = _exchange_message(session, "wss://test.local", "test msg")

        mock_client_cls.assert_called_once()
        _, kwargs = mock_client_cls.call_args
        assert kwargs["verify_tls"] is False
        assert resp == "response msg"


def test_detection_package_exports():
    """Verify all 9 detection functions are publicly exposed in stealthix.detection."""
    expected_detectors = [
        "detect_sqli",
        "detect_nosqli",
        "detect_newsql",
        "detect_idor",
        "detect_websocket",
        "detect_graphql",
        "detect_graphqli",
        "detect_searchqli",
        "detect_timeseriesqli",
    ]
    for name in expected_detectors:
        assert hasattr(det, name), f"Missing {name} in stealthix.detection"
        assert callable(getattr(det, name))


def test_evasion_package_exports():
    """Verify comprehensive evasion classes and functions are exported in stealthix.evasion."""
    expected = [
        "AdaptiveCandidate",
        "ChainOptimizer",
        "EncodingChain",
        "MLWAFDetector",
        "MutationStrategy",
        "PolymorphicEncoder",
        "RequestSmuggler",
        "SmugglingTechnique",
        "TimingAnalyzer",
        "TimingProfile",
        "WAFResponseFeatures",
        "build_retry_candidates",
        "infer_waf_vendor",
        "record_adaptive_result",
        "resolve_tamper_pipeline",
        "tamper_payload",
    ]
    for name in expected:
        assert hasattr(ev, name), f"Missing {name} in stealthix.evasion"


def test_oob_package_exports():
    """Verify OOB listeners and providers are exported in stealthix.oob."""
    expected = [
        "DnsCallbackListener",
        "LocalDnsOASTProvider",
        "OASTConfirmation",
        "OASTInteraction",
        "OASTProvider",
        "PassiveOASTProvider",
        "get_global_listener",
        "provider_from_env",
    ]
    for name in expected:
        assert hasattr(oob, name), f"Missing {name} in stealthix.oob"


def test_graphql_history_metadata_enrichment():
    """Verify _post_json records headers and status_code in history metadata."""
    session = ScanSession(SessionConfig(base_url="http://test.local/graphql"))

    fake_resp = MagicMock()
    fake_resp.status_code = 200
    fake_resp.headers = {"Content-Type": "application/json", "X-Custom": "val"}
    fake_resp.text = '{"data":{"__typename":"Query"}}'

    with patch("requests.post", return_value=fake_resp):
        body, elapsed = _post_json(session, "http://test.local/graphql", {"query": "{__typename}"})

    assert body == fake_resp.text
    history = session.history.to_list()
    assert len(history) >= 1
    last = history[-1]
    assert last["metadata"]["status_code"] == 200
    assert last["metadata"]["headers"]["X-Custom"] == "val"


def test_tui_app_init_includes_all_payload_families():
    """Verify app.init exposes all 7 technique payload families."""
    res = handle_core_action("app.init", {})
    assert res is not None
    data = json.loads(res["data_json"])
    families = data["payload_families"]
    for fam in ["sqli", "nosqli", "newsql", "error_based", "union_based", "time_based", "stacked"]:
        assert fam in families
        assert fam in data["default_payloads"]
        assert len(data["default_payloads"][fam]) > 0


def test_load_config_handles_utf8(tmp_path: Path):
    """Verify load_config reads YAML with UTF-8 characters properly."""
    cfg_file = tmp_path / "stealthix.yaml"
    cfg_file.write_text("url: 'https://test.local/vuln?q=🚀'\nrisk: 2\n", encoding="utf-8")

    cfg = load_config(cfg_file)
    assert cfg.url == "https://test.local/vuln?q=🚀"
    assert cfg.risk == 2
