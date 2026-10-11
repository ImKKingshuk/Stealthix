"""
Comprehensive tests for reconnaissance subsystem robustness, CLI commands, and error handling.
"""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.recon.endpoint_discovery import EndpointDiscovery
from stealthix.recon.engine import ReconEngine
from stealthix.recon.models import DiscoveredEndpoint, ReconConfig, TechnologyMatch
from stealthix.recon.tech_detector import TechDetector
from stealthix_headless_cli.commands.recon import (
    format_recon_output,
    recon_endpoints,
    recon_tech,
)
from stealthix_headless_cli.main import cli


def test_recon_tech_with_dict_and_model_results():
    """Verify recon_tech cleanly processes both dicts and model instances."""
    args = argparse.Namespace(
        url="http://test.local",
        proxy=None,
        timeout=5.0,
        verify_tls=False,
    )

    mock_results = {
        "technologies": [
            {
                "category": "web_server",
                "name": "nginx",
                "version": "1.24.0",
                "confidence": 0.95,
                "evidence": [{"type": "header", "key": "server"}],
            },
            TechnologyMatch(
                category="language",
                name="python",
                version="3.13.0",
                confidence=0.88,
                evidence=[{"type": "body", "pattern": "python"}],
            ),
        ],
        "fingerprint": {"server": "nginx/1.24.0", "powered_by": "python/3.13.0"},
        "elapsed": 0.42,
    }

    with patch.object(ReconEngine, "run", return_value=mock_results):
        data = recon_tech(args)

    assert data["target"] == "http://test.local"
    assert len(data["technologies"]) == 2
    assert data["technologies"][0]["name"] == "nginx"
    assert data["technologies"][0]["evidence_count"] == 1
    assert data["technologies"][1]["name"] == "python"
    assert data["technologies"][1]["evidence_count"] == 1
    assert data["fingerprint"]["server"] == "nginx/1.24.0"


def test_recon_endpoints_with_dict_and_model_results():
    """Verify recon_endpoints cleanly processes both dicts and model instances."""
    args = argparse.Namespace(
        url="http://test.local",
        proxy=None,
        timeout=5.0,
        verify_tls=False,
        wordlist=None,
        max_endpoints=50,
        depth=1,
    )

    mock_results = {
        "endpoints": [
            {
                "url": "http://test.local/admin",
                "status_code": 200,
                "response_size": 1024,
                "response_time": 0.05,
                "category": "admin",
                "confidence": 0.9,
            },
            DiscoveredEndpoint(
                url="http://test.local/api",
                status_code=401,
                response_size=256,
                response_time=0.03,
                category="api",
                confidence=0.85,
            ),
        ],
        "elapsed": 0.35,
    }

    with patch.object(ReconEngine, "run", return_value=mock_results):
        data = recon_endpoints(args)

    assert data["target"] == "http://test.local"
    assert len(data["endpoints"]) == 2
    assert data["endpoints"][0]["url"] == "http://test.local/admin"
    assert data["endpoints"][0]["status_code"] == 200
    assert data["endpoints"][1]["url"] == "http://test.local/api"
    assert data["endpoints"][1]["status_code"] == 401


def test_format_recon_output_text_and_json():
    """Verify format_recon_output formats tech, fingerprint, and endpoint results."""
    data = {
        "target": "http://example.com",
        "elapsed": 1.25,
        "technologies": [
            {
                "category": "web_server",
                "name": "apache",
                "version": "2.4.52",
                "confidence": 0.9,
            }
        ],
        "fingerprint": {
            "server": "apache/2.4.52",
            "powered_by": "PHP/8.1",
            "os": "Linux",
            "waf_hints": ["cloudflare"],
            "database_hints": ["mysql"],
        },
        "endpoints": [
            {
                "url": "http://example.com/api/v1",
                "status_code": 200,
                "category": "api",
                "confidence": 0.95,
            }
        ],
    }

    json_out = format_recon_output(data, "json")
    assert '"target": "http://example.com"' in json_out
    assert '"apache"' in json_out

    text_out = format_recon_output(data, "text")
    assert "Target: http://example.com" in text_out
    assert "Technologies Detected: 1" in text_out
    assert "apache" in text_out
    assert "Server: apache/2.4.52" in text_out
    assert "Powered-By: PHP/8.1" in text_out
    assert "OS: Linux" in text_out
    assert "WAF Hints: cloudflare" in text_out
    assert "Database Hints: mysql" in text_out
    assert "Endpoints Discovered: 1" in text_out
    assert "[200] http://example.com/api/v1" in text_out


def test_recon_engine_preserves_both_top_level_and_session_errors():
    """Verify ReconEngine.run merges session errors without overwriting engine exceptions."""
    session = ScanSession(SessionConfig(base_url="http://test.local"))
    session.metadata["recon_errors"] = ["Pre-existing session recon warning"]

    engine = ReconEngine(session)

    # Force an exception during technology detection
    with patch.object(engine, "_run_tech_detection", side_effect=RuntimeError("Simulated engine crash")):
        results = engine.run()

    errors = results.get("errors", [])
    assert any("Reconnaissance failed: Simulated engine crash" in err for err in errors)
    assert any("Pre-existing session recon warning" in err for err in errors)


def test_endpoint_discovery_does_not_duplicate_successful_head():
    """Verify that EndpointDiscovery does NOT issue a redundant GET when HEAD succeeds."""
    session = ScanSession(SessionConfig(base_url="http://test.local"))
    discovery = EndpointDiscovery(session, ReconConfig())

    requests_made: list[tuple[str, str]] = []

    def fake_make_request(sess: Any, method: str, url: str, **kwargs: Any):
        requests_made.append((method, url))
        sess.history.add(
            url,
            method,
            "200",
            0.02,
            {"status_code": 200, "headers": {"Content-Type": "text/html"}},
        )
        return ("", 0.02)

    with patch("stealthix.recon.endpoint_discovery.make_request", side_effect=fake_make_request):
        endpoint = discovery._probe_endpoint("/robots.txt", "common", use_head=True)

    assert endpoint is not None
    assert requests_made == [("HEAD", "http://test.local/robots.txt")]
    assert len(requests_made) == 1  # No duplicate GET!


def test_endpoint_discovery_retries_get_on_head_405_or_501():
    """Verify that EndpointDiscovery retries with GET when HEAD is rejected with 405."""
    session = ScanSession(SessionConfig(base_url="http://test.local"))
    discovery = EndpointDiscovery(session, ReconConfig())

    requests_made: list[tuple[str, str]] = []

    def fake_make_request(sess: Any, method: str, url: str, **kwargs: Any):
        requests_made.append((method, url))
        if method == "HEAD":
            sess.history.add(
                url,
                method,
                "405",
                0.01,
                {"status_code": 405, "headers": {}},
            )
            return ("", 0.01)
        else:
            sess.history.add(
                url,
                method,
                "200",
                0.03,
                {"status_code": 200, "headers": {"Content-Type": "text/plain"}},
            )
            return ("valid response content", 0.03)

    with patch("stealthix.recon.endpoint_discovery.make_request", side_effect=fake_make_request):
        endpoint = discovery._probe_endpoint("/admin", "admin", use_head=True)

    assert endpoint is not None
    assert requests_made == [
        ("HEAD", "http://test.local/admin"),
        ("GET", "http://test.local/admin"),
    ]


def test_tech_detector_reuses_session_history_metadata():
    """Verify TechDetector reuses headers from session history without redundant HTTP request."""
    session = ScanSession(
        SessionConfig(
            base_url="http://test.local",
            headers={"Authorization": "Bearer token123"},
            cookies={"session": "abc"},
        )
    )
    detector = TechDetector(session)

    # Simulate prior make_request populating history with nginx server header
    def fake_make_request(sess: Any, method: str, url: str, **kwargs: Any):
        sess.history.add(
            url,
            method,
            "200",
            0.05,
            {"status_code": 200, "headers": {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1"}},
        )
        return ("<html><body>Hello</body></html>", 0.05)

    with patch("stealthix.recon.tech_detector.make_request", side_effect=fake_make_request), \
         patch("requests.get") as mock_requests_get:
        matches = detector.detect()

    # requests.get should NOT have been called because headers were in session history!
    mock_requests_get.assert_not_called()
    assert any(m.name == "nginx" for m in matches)
    assert any(m.name.lower() == "php" for m in matches)


def test_cli_recon_commands_execute_cleanly(capsys: pytest.CaptureFixture):
    """Verify stealthix recon tech and recon endpoints run end-to-end via CLI entrypoint."""
    mock_tech_results = {
        "technologies": [
            {
                "category": "web_server",
                "name": "caddy",
                "version": "2.7.0",
                "confidence": 0.99,
                "evidence": [],
            }
        ],
        "fingerprint": {"server": "caddy/2.7.0"},
        "elapsed": 0.1,
    }

    mock_endpoint_results = {
        "endpoints": [
            {
                "url": "http://test.local/api/health",
                "status_code": 200,
                "response_size": 24,
                "response_time": 0.02,
                "category": "api",
                "confidence": 0.9,
            }
        ],
        "elapsed": 0.1,
    }

    with patch.object(ReconEngine, "run", return_value=mock_tech_results):
        exit_code = cli(["recon", "tech", "-u", "http://test.local"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "caddy" in captured.out

    with patch.object(ReconEngine, "run", return_value=mock_endpoint_results):
        exit_code = cli(["recon", "endpoints", "-u", "http://test.local"])
    assert exit_code == 0
    captured = capsys.readouterr()
    assert "http://test.local/api/health" in captured.out
