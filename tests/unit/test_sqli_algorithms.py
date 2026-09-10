from stealthix.core.session import ScanSession, SessionConfig
from stealthix.core.targeting import InjectionPoint
from stealthix.detection import sqli as sqli_module


def test_boolean_based_detects(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    point = InjectionPoint(name="id", location="query")

    def fake_request(*args, **kwargs):
        url = args[1]
        if "1=2" in url or "1%3D2" in url or "1%253D2" in url:
            return "x" * 10, 0.01
        return "x" * 200, 0.01

    monkeypatch.setattr(sqli_module, "_make_request", fake_request)
    monkeypatch.setattr(sqli_module, "load_rust_core", lambda: {})
    findings = sqli_module._boolean_based(session, point)
    assert findings and findings[0].kind == "sqli-boolean"


def test_time_based_detects(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", risk=1))
    point = InjectionPoint(name="id", location="query")
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] <= 3:
            return "ok", 0.1
        return "ok", 2.5

    monkeypatch.setattr(sqli_module, "_make_request", fake_request)
    monkeypatch.setattr(sqli_module, "load_payloads", lambda _kind: ["' OR SLEEP(3)--"])
    monkeypatch.setattr(sqli_module, "load_rust_core", lambda: {})
    findings = sqli_module._time_based(session, point)
    assert findings and findings[0].kind == "sqli-time"


def test_union_based_detects(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=3))
    point = InjectionPoint(name="id", location="query")

    def fake_request(*args, **kwargs):
        url = args[1]
        if "ORDER BY 3" in url:
            return "SQL error", 0.01
        if "stealthix_marker" in url:
            return "stealthix_marker", 0.01
        return "baseline", 0.01

    monkeypatch.setattr(sqli_module, "_make_request", fake_request)
    monkeypatch.setattr(sqli_module, "load_payloads", lambda _kind: [])
    monkeypatch.setattr(sqli_module, "load_rust_core", lambda: {})
    findings = sqli_module._union_based(session, point)
    assert findings and findings[0].kind == "sqli-union"


def test_oob_based_detects(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=4))
    monkeypatch.setenv("STEALTHIX_OOB_DOMAIN", "example.com")

    def fake_request(*args, **kwargs):
        return args[1], 0.01

    monkeypatch.setattr(sqli_module, "_make_request", fake_request)
    monkeypatch.setattr(sqli_module, "load_rust_core", lambda: {})
    findings = sqli_module._oob_based(session)
    assert findings and findings[0].kind == "sqli-oob"


def test_oob_based_uses_dbms_specific_templates(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=4, dbms="postgresql"))
    monkeypatch.setenv("STEALTHIX_OOB_DOMAIN", "example.com")

    def fake_request(*args, **kwargs):
        return args[1], 0.01

    monkeypatch.setattr(sqli_module, "_make_request", fake_request)
    monkeypatch.setattr(sqli_module, "load_rust_core", lambda: {})
    findings = sqli_module._oob_based(session)

    assert findings and findings[0].details["strategies"] == ["dns-copy-program"]
    assert "nslookup" in findings[0].details["attempts"][0]["payload"]
