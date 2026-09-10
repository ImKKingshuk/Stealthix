from urllib.parse import parse_qs, urlparse

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.detection.common import detect_idor


def test_detect_idor(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com/?id=1"))

    def fake_request(_session, url, *_args, **_kwargs):
        value = parse_qs(urlparse(url).query).get("id", ["1"])[0]
        if value == "1":
            body = "A"
        elif value == "2":
            body = "B" * 100
        else:
            body = "not found"
        return body, 0.01

    monkeypatch.setattr("stealthix.detection.common._make_request", fake_request)
    findings = detect_idor(session)
    assert findings and findings[0].kind == "idor"


def test_detect_idor_ignores_alternate_that_matches_invalid_control(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com/?id=1"))

    def fake_request(_session, url, *_args, **_kwargs):
        value = parse_qs(urlparse(url).query).get("id", ["1"])[0]
        if value == "1":
            body = "A" * 120
        else:
            body = "not found"
        return body, 0.01

    monkeypatch.setattr("stealthix.detection.common._make_request", fake_request)
    assert detect_idor(session) == []
