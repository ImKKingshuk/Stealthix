import runpy
import sys

from stealthix.core.engine import Finding, ScanResult


def test_main_module(monkeypatch):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[Finding(kind="sqli", target="t")]
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    monkeypatch.setattr(
        sys, "argv", ["stealthix", "scan", "-u", "http://example.com", "--report", "json"]
    )
    try:
        runpy.run_module("stealthix.__main__", run_name="__main__")
    except SystemExit as exc:
        assert exc.code in (0, 1)


def test_main_module_allows_session_load(monkeypatch, tmp_path):
    from stealthix.core.session import ScanSession, SessionConfig

    saved = ScanSession(SessionConfig(base_url="http://example.com"))
    session_path = tmp_path / "session.json"
    saved.save(str(session_path))

    class DummyEngine:
        def __init__(self, session):
            assert session.config.base_url == "http://example.com"
            self.session = session

        def detect(self):
            return ScanResult(target=self.session.config.base_url, findings=[])

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    monkeypatch.setattr(
        sys, "argv", ["stealthix", "scan", "--session-load", str(session_path), "--report", "json"]
    )
    try:
        runpy.run_module("stealthix.__main__", run_name="__main__")
    except SystemExit as exc:
        assert exc.code == 0
