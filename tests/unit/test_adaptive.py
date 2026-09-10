from stealthix.core.session import ScanSession, SessionConfig
from stealthix.evasion.adaptive import (
    build_retry_candidates,
    resolve_tamper_pipeline,
    tamper_payload,
)


def test_resolve_tamper_pipeline_uses_vendor_profile_and_body_format():
    session = ScanSession(SessionConfig(base_url="http://example.test", body_format="json"))
    session.metadata["waf"] = {"detected": "modsecurity"}

    pipeline = resolve_tamper_pipeline(session, blocked=True, body_format="json")

    assert "versionedmorekeywords" in pipeline
    assert "charunicodeescape" in pipeline


def test_tamper_payload_returns_payload_and_header_mutations(monkeypatch):
    monkeypatch.setattr("stealthix.evasion.adaptive.load_rust_core", lambda: {})
    session = ScanSession(
        SessionConfig(
            base_url="http://example.test", tamper_pipeline=["space2comment", "xforwardedfor"]
        )
    )

    payload, headers, applied = tamper_payload(session, "UNION SELECT")

    assert payload == "UNION/**/SELECT"
    assert "X-Forwarded-For" in headers
    assert applied == ["space2comment", "xforwardedfor"]


def test_build_retry_candidates_cover_hpp_json_and_fragmentation(monkeypatch):
    monkeypatch.setattr("stealthix.evasion.adaptive.load_rust_core", lambda: {})
    session = ScanSession(
        SessionConfig(
            base_url="http://example.test", method="POST", body_format="json", tamper_retry_budget=5
        )
    )

    candidates = build_retry_candidates(
        session,
        url="http://example.test/search?q=1",
        data={"payload": "1 UNION SELECT"},
        headers={"X-Test": "1"},
        method="POST",
        body_format="json",
        multipart_fields=set(),
    )

    names = {candidate.name for candidate in candidates}
    assert "tamper-pipeline" in names
    assert "http-parameter-pollution" in names
    assert "json-unicode-escape" in names
    assert any(candidate.transport == "fragmented" for candidate in candidates)
