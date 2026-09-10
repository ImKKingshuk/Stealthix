from types import SimpleNamespace

from stealthix.core.session import ScanSession, SessionConfig


class DummyResponse:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.headers = {}


def test_request_cache_dedupes_requests(monkeypatch):
    from stealthix.extraction.base import _make_request

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    monkeypatch.setenv("STEALTHIX_CACHE", "1")
    monkeypatch.setenv("STEALTHIX_CACHE_TTL", "60")

    calls = {"n": 0}

    def fake_get(*args, **kwargs):
        calls["n"] += 1
        return DummyResponse("ok")

    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(get=fake_get, post=None),
    )
    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})

    body1, _ = _make_request(session, "http://example.com/cachetest")
    body2, _ = _make_request(session, "http://example.com/cachetest")
    assert body1 == body2 == "ok"
    assert calls["n"] == 1
