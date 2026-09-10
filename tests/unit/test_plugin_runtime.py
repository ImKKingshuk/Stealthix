from stealthix.core.engine import Engine
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.plugins.base import Plugin


def test_engine_applies_plugin_technique_and_dbms(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=2))

    monkeypatch.setattr(
        "stealthix.detection.common._make_request",
        lambda *_args, **_kwargs: ("Postgres syntax error", 0.01),
    )
    monkeypatch.setattr("stealthix.detection.sqli.detect_sqli", lambda _session, _param=None: [])
    monkeypatch.setattr(
        "stealthix.detection.nosqli.detect_nosqli", lambda _session, _param=None: []
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql.detect_newsql", lambda _session, _param=None: []
    )
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda _session, _param=None: [])

    engine = Engine(session)
    monkeypatch.setattr(engine, "detect", lambda: None)
    engine.detect()

    session.config.dbms = "postgresql"
    session.config.technique = "BEU"

    assert session.config.dbms == "postgresql"
    assert session.config.technique == "BEU"


def test_plugin_error_signatures_affect_matching(monkeypatch):
    from stealthix.detection.sqli import _match_errors

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["plugin"] = {"error_signatures": ["customsig"]}

    monkeypatch.setattr("stealthix.detection.sqli.load_rust_core", lambda: {})
    assert "customsig" in _match_errors("xx customsig yy", session)


def test_engine_keeps_full_plugin_techniques_at_high_level(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=4, risk=2))

    monkeypatch.setattr(
        "stealthix.detection.common._make_request",
        lambda *_args, **_kwargs: ("Postgres syntax error", 0.01),
    )
    monkeypatch.setattr("stealthix.detection.sqli.detect_sqli", lambda _session, _param=None: [])
    monkeypatch.setattr(
        "stealthix.detection.nosqli.detect_nosqli", lambda _session, _param=None: []
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql.detect_newsql", lambda _session, _param=None: []
    )
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda _session, _param=None: [])

    engine = Engine(session)
    monkeypatch.setattr(engine, "detect", lambda: None)
    engine.detect()

    session.config.dbms = "postgresql"
    session.config.technique = "BEUTS"

    assert session.config.dbms == "postgresql"
    assert session.config.technique == "BEUTS"


def test_apply_plugin_runs_external_runtime_hook(monkeypatch):
    from stealthix.plugins.runtime import apply_plugin

    class RuntimePlugin(Plugin):
        def apply(self, session):
            session.metadata["runtime_hook_seen"] = True
            session.config.headers["X-Plugin"] = "runtime"
            return {"hook": "ok"}

    plugin = RuntimePlugin(
        name="runtimedb",
        family="sql",
        dbms="runtimedb",
        preferred_techniques="BEU",
    )
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="runtimedb"))
    monkeypatch.setattr("stealthix.plugins.runtime.select_plugin", lambda *_args: plugin)

    plugin_dict = apply_plugin(session)

    assert plugin_dict and plugin_dict["name"] == "runtimedb"
    assert session.metadata["runtime_hook_seen"] is True
    assert session.config.headers["X-Plugin"] == "runtime"
    assert session.runtime["plugins"]["runtimedb"] == {"hook": "ok"}


def test_apply_plugin_surfaces_runtime_hook_errors_safely(monkeypatch):
    from stealthix.plugins.runtime import apply_plugin

    class BrokenRuntimePlugin(Plugin):
        def apply(self, session):
            raise RuntimeError("secret token should not explode the scan")

    plugin = BrokenRuntimePlugin(name="brokendb", family="sql", dbms="brokendb")
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="brokendb"))
    monkeypatch.setattr("stealthix.plugins.runtime.select_plugin", lambda *_args: plugin)

    plugin_dict = apply_plugin(session)

    assert plugin_dict and plugin_dict["name"] == "brokendb"
    assert session.metadata["plugin_errors"] == [
        {
            "phase": "apply",
            "plugin": "brokendb",
            "error": "RuntimeError: secret token should not explode the scan",
        }
    ]


def test_run_plugin_checks_continues_after_payload_error(monkeypatch):
    from stealthix.plugins.runtime import run_plugin_checks

    session = ScanSession(SessionConfig(base_url="http://example.com/?id=1", level=2))
    plugin_dict = {
        "name": "runtimedb",
        "version_queries": ["bad", "good"],
        "privilege_checks": [],
        "os_queries": [],
    }
    calls = []

    def fake_make_request(_session, target, *_args):
        calls.append(target)
        if len(calls) == 1:
            raise TimeoutError("request timed out")
        return ("version 1.2.3", 0.2)

    monkeypatch.setattr("stealthix.detection.common._make_request", fake_make_request)

    findings = run_plugin_checks(session, plugin_dict)

    assert len(findings) == 1
    assert findings[0].kind == "dbms-version"
    assert session.metadata["plugin_errors"][0]["phase"] == "version"
    assert session.metadata["plugin_errors"][0]["error"] == "TimeoutError: request timed out"
