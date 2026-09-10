from stealthix.core.session import ScanSession, SessionConfig
from stealthix.detection import detect_newsql, detect_nosqli, detect_sqli
from stealthix.utils import load_payloads


class DummyResponse:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200


def test_load_payloads():
    assert load_payloads("sqli")
    assert load_payloads("nosqli")
    assert load_payloads("newsql")


def test_detection(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    def fake_get_sqli(*args, **kwargs):
        return DummyResponse("SQL error")

    def fake_get_nosqli(*args, **kwargs):
        return DummyResponse("MongoDB error")

    def fake_get_newsql(*args, **kwargs):
        return DummyResponse("CockroachDB error")

    def fake_post(*args, **kwargs):
        return DummyResponse("SQL error")

    monkeypatch.setattr("stealthix.detection.sqli.load_rust_core", lambda: {})
    monkeypatch.setattr("stealthix.detection.nosqli.load_rust_core", lambda: {})
    monkeypatch.setattr("stealthix.detection.newsql.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.detection.sqli._make_request", lambda *args, **kwargs: ("SQL error", 0.01)
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli._make_request", lambda *args, **kwargs: ("MongoDB error", 0.01)
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql._make_request",
        lambda *args, **kwargs: ("CockroachDB error", 0.01),
    )

    assert detect_sqli(session)
    assert detect_nosqli(session)
    assert detect_newsql(session)


def test_detect_sqli_does_not_report_generic_finding_from_delay_alone(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    monkeypatch.setattr(
        "stealthix.detection.sqli.resolve_payloads", lambda *_args, **_kwargs: ["' OR SLEEP(3)--"]
    )
    monkeypatch.setattr(
        "stealthix.detection.sqli._make_request", lambda *args, **kwargs: ("ok", 4.2)
    )
    monkeypatch.setattr("stealthix.detection.sqli._boolean_based", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.sqli._time_based", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.sqli._error_based", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.sqli._union_based", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.sqli._stacked", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.sqli.load_rust_core", lambda: {})

    assert detect_sqli(session) == []


def test_detect_nosqli_mongo_requires_more_than_timing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mongodb"))

    monkeypatch.setattr("stealthix.detection.nosqli.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.detection.nosqli.resolve_payloads",
        lambda *_args, **_kwargs: ['{"$where": "sleep(5000)"}'],
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli._make_request", lambda *args, **kwargs: ("ok", 3.2)
    )

    assert detect_nosqli(session) == []


def test_detect_newsql_uses_baseline_aware_timing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="cockroachdb"))
    calls = {"count": 0}

    def fake_request(*args, **kwargs):
        calls["count"] += 1
        if calls["count"] <= 3:
            return "ok", 0.1
        return "ok", 2.4

    monkeypatch.setattr("stealthix.detection.newsql.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.detection.newsql.resolve_payloads",
        lambda *_args, **_kwargs: ["'; SELECT pg_sleep(3);--"],
    )
    monkeypatch.setattr("stealthix.detection.newsql._make_request", fake_request)

    findings = detect_newsql(session)
    assert findings and findings[0].kind == "newsql"
    assert "timing-outlier" in findings[0].details["signals"]


def test_detect_nosqli_redis_uses_backend_specific_catalog(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="redis", risk=1))

    monkeypatch.setattr("stealthix.detection.nosqli.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.detection.nosqli._make_request",
        lambda *args, **kwargs: ("redis_version:7.0", 0.01),
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli.get_advanced_payloads",
        lambda backend: ["PING"] if backend == "redis" else [],
    )

    findings = detect_nosqli(session)

    assert findings and findings[0].kind == "nosqli-redis"
    assert findings[0].details["backend"] == "redis"
