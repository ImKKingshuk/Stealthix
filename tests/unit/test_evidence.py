from __future__ import annotations

import json

from stealthix.core.evidence import (
    BackendFingerprintEvidence,
    FindingEvidenceBundle,
    PayloadEvidence,
    RequestEvidence,
    ResponseEvidence,
    TimingEvidence,
    attach_evidence,
)
from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.json_report import render_json
from stealthix.reporting.presentation import summarize_finding


def test_request_response_evidence_redacts_and_accepts_legacy_pair_shape() -> None:
    request = RequestEvidence.from_dict(
        {
            "method": "POST",
            "url": "http://example.test/login?id=1",
            "headers": {"Authorization": "Bearer token", "X-Test": "1"},
            "body": "A" * 700,
        }
    )
    response = ResponseEvidence.from_dict(
        {
            "status": "500",
            "headers": {"Set-Cookie": "sid=secret", "Content-Type": "text/plain"},
            "body": "SQLSTATE[42000] syntax error",
            "elapsed": "34.5",
            "waf_hints": ["sql-error"],
        }
    )

    request_data = request.to_dict()
    response_data = response.to_dict()

    assert request_data["headers"]["Authorization"] == "[REDACTED]"
    assert request_data["headers"]["X-Test"] == "1"
    assert request_data["body_excerpt"].endswith("...")
    assert len(request_data["body_sha256"]) == 64
    assert response_data["status_code"] == 500
    assert response_data["headers"]["Set-Cookie"] == "[REDACTED]"
    assert response.to_pair_dict()["body"].startswith("SQLSTATE")


def test_finding_evidence_bundle_round_trips_and_builds_compatibility_pairs() -> None:
    bundle = FindingEvidenceBundle(
        requests=[
            RequestEvidence.from_dict(
                {
                    "method": "GET",
                    "url": "http://example.test/?id=1'",
                    "headers": {"Cookie": "sid=secret"},
                }
            )
        ],
        responses=[ResponseEvidence.from_dict({"status": 500, "body": "syntax error"})],
        payloads=[PayloadEvidence.from_dict({"parameter": "id", "payload": "1' OR '1'='1"})],
        timings=[TimingEvidence.from_dict({"baseline_ms": 100, "observed_ms": 350})],
        backend_fingerprints=[
            BackendFingerprintEvidence.from_dict(
                {"dbms": "mysql", "confidence": "high", "signals": ["sqlstate"]}
            )
        ],
        summary="SQL error response changed with injected payload",
    )

    data = FindingEvidenceBundle.from_dict(bundle.to_dict()).to_dict()

    assert data["schema_version"] == "1.0"
    assert data["evidence_count"] == 1
    assert data["evidence_pairs"][0]["request"]["headers"]["Cookie"] == "[REDACTED]"
    assert data["timings"][0]["delta_ms"] == 250.0
    assert data["backend_fingerprints"][0]["dbms"] == "mysql"


def test_attach_evidence_updates_details_and_reports_normalized_bundle() -> None:
    finding = Finding(kind="sqli-error", target="http://example.test/?id=1", parameter="id")
    bundle = FindingEvidenceBundle(
        requests=[RequestEvidence.from_dict({"method": "GET", "url": finding.target})],
        responses=[ResponseEvidence.from_dict({"status": 500, "body": "SQLSTATE[42000]"})],
    )

    attached = attach_evidence(finding, bundle)
    view = summarize_finding(attached, {"generated_at": "2026-05-11T00:00:00Z"})

    assert attached.details["evidence_count"] == 1
    assert attached.details["evidence_pairs"][0]["response"]["body"] == "SQLSTATE[42000]"
    assert view["evidence_bundle"]["responses"][0]["status_code"] == 500
    assert view["evidence_pairs"][0]["request"]["url"] == finding.target


def test_render_json_can_filter_normalized_evidence_bundle() -> None:
    finding = attach_evidence(
        Finding(kind="sqli-error", target="http://example.test/?id=1"),
        {
            "requests": [{"method": "GET", "url": "http://example.test/?id=1"}],
            "responses": [{"status": 500, "body": "SQLSTATE"}],
        },
    )
    result = ScanResult(target="http://example.test", findings=[finding], metadata={})

    with_evidence = json.loads(render_json(result, include_evidence=True))
    without_evidence = json.loads(render_json(result, include_evidence=False))

    assert "evidence_bundle" in with_evidence["findings"][0]
    assert "evidence_bundle" not in without_evidence["findings"][0]
    assert "evidence_bundle" not in without_evidence["findings"][0]["details"]
