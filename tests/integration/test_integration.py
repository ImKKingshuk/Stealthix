import os

import pytest

from stealthix.core.engine import Engine
from stealthix.core.session import ScanSession, SessionConfig


def _is_reachable(url: str) -> bool:
    import requests

    try:
        requests.get(url, timeout=2)
        return True
    except Exception:
        return False


@pytest.mark.live
def test_integration_detect():
    url = os.environ.get("STEALTHIX_INTEGRATION_URL")
    if not url:
        pytest.skip("STEALTHIX_INTEGRATION_URL not set")
    session = ScanSession(SessionConfig(base_url=url))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url


@pytest.mark.live
def test_integration_dvwa():
    url = os.environ.get("STEALTHIX_DVWA_URL") or "http://localhost:8081"
    if not _is_reachable(url):
        pytest.skip("DVWA not reachable")
    session = ScanSession(SessionConfig(base_url=url))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url


@pytest.mark.live
def test_integration_bwapp():
    url = os.environ.get("STEALTHIX_BWAPP_URL") or "http://localhost:8082"
    if not _is_reachable(url):
        pytest.skip("bWAPP not reachable")
    session = ScanSession(SessionConfig(base_url=url))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url


@pytest.mark.live
def test_integration_sqlilabs():
    url = os.environ.get("STEALTHIX_SQLILABS_URL") or "http://localhost:8083"
    if not _is_reachable(url):
        pytest.skip("SQLi-labs not reachable")
    session = ScanSession(SessionConfig(base_url=url))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url


@pytest.mark.live
def test_integration_benchmark():
    url = os.environ.get("STEALTHIX_BENCHMARK_URL") or "http://localhost:8081"
    if not _is_reachable(url):
        pytest.skip("Benchmark target not reachable")
    session = ScanSession(SessionConfig(base_url=url, risk=2, level=3))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url


@pytest.mark.live
def test_integration_known_vulnerable_endpoint():
    url = os.environ.get("STEALTHIX_KNOWN_VULN_URL")
    if not url:
        pytest.skip("STEALTHIX_KNOWN_VULN_URL not set")
    if not _is_reachable(url):
        pytest.skip("Known vulnerable endpoint not reachable")
    session = ScanSession(SessionConfig(base_url=url, risk=3, level=4))
    engine = Engine(session)
    result = engine.detect()
    assert result.target == url
    assert result.findings
