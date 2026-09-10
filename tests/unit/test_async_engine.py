import asyncio

from stealthix.core.async_engine import AsyncEngine
from stealthix.core.models import Finding
from stealthix.core.session import ScanSession, SessionConfig


def test_async_engine_exposes_awaitable_scan_api(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql", threads=1))

    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)
    monkeypatch.setattr("stealthix.core.engine.discover_target_params", lambda _session: [])
    monkeypatch.setattr(
        "stealthix.detection.sqli.detect_sqli",
        lambda _session, _param=None: [Finding(kind="sqli", target="http://example.com")],
    )
    monkeypatch.setattr("stealthix.detection.nosqli.detect_nosqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.newsql.detect_newsql", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda *_args, **_kwargs: [])

    result = asyncio.run(AsyncEngine(session).detect())

    assert result.target == "http://example.com"
    assert [finding.kind for finding in result.findings] == ["sqli"]
