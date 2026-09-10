from __future__ import annotations

from typing import Any, cast

from stealthix.core.models import Finding, ScanResult
from stealthix.core.session import ScanSession
from stealthix.reporting.scoring import score_finding


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def finding_to_dict(finding: Finding) -> dict[str, object]:
    cvss = float(score_finding(finding))
    return {
        "kind": finding.kind,
        "target": finding.target,
        "details": finding.details,
        "parameter": finding.parameter,
        "location": finding.location,
        "cvss": cvss,
        "severity": severity_from_score(cvss),
    }


def result_to_dict(result: ScanResult) -> dict[str, object]:
    return {
        "target": result.target,
        "findings": [finding_to_dict(item) for item in result.findings],
        "metadata": result.metadata,
    }


def result_from_payload(payload: dict[str, object]) -> ScanResult:
    findings = [
        Finding(
            kind=str(item.get("kind") or "unknown"),
            target=str(item.get("target") or payload.get("target") or "unknown"),
            details=cast(
                dict[str, Any], item.get("details") if isinstance(item.get("details"), dict) else {}
            ),
            parameter=item.get("parameter"),
            location=item.get("location"),
        )
        for item in cast(
            list[dict[str, Any]],
            payload.get("findings") if isinstance(payload.get("findings"), list) else [],
        )
        if isinstance(item, dict)
    ]
    metadata = payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    metadata = metadata if isinstance(metadata, dict) else {}
    return ScanResult(
        target=str(payload.get("target") or ""),
        findings=findings,
        metadata=cast(dict[str, Any], metadata),
    )


def session_to_dict(session: ScanSession) -> dict[str, object]:
    return cast(dict[str, object], session.to_private_payload())


def session_from_payload(payload: dict[str, object]) -> ScanSession:
    return ScanSession.from_payload(cast(dict[str, Any], payload))
