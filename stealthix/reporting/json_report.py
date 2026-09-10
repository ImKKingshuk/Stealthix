from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context

try:
    from jsonschema import ValidationError, validate

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False


def render_json(
    result: ScanResult,
    format: str = "detailed",
    validate_schema: bool = False,
    include_metadata: bool = True,
    include_evidence: bool = True,
    include_timeline: bool = True,
    include_recon: bool = True,
) -> str:
    """
    Render scan result as JSON.

    Args:
        result: ScanResult to render
        format: Output format (detailed, minimal, machine_readable)
        validate_schema: Whether to validate against JSON Schema
        include_metadata: Include full metadata
        include_evidence: Include evidence pairs
        include_timeline: Include timeline
        include_recon: Include reconnaissance data

    Returns:
        JSON string
    """
    report = build_report_context(result)

    # Apply format transformation
    if format == "minimal":
        payload = _transform_to_minimal(report)
    elif format == "machine_readable":
        payload = _transform_to_machine_readable(report)
    else:
        payload = report

    # Filter based on options
    if not include_metadata:
        payload = _filter_metadata(payload)
    if not include_evidence:
        payload = _filter_evidence(payload)
    if not include_timeline:
        payload.pop("timeline", None)
    if not include_recon:
        payload.pop("reconnaissance", None)

    # Validate if requested
    if validate_schema and JSONSCHEMA_AVAILABLE:
        schema_path = _get_schema_path(format)
        if schema_path.exists():
            schema = json.loads(schema_path.read_text())
            try:
                validate(instance=payload, schema=schema)
            except ValidationError as e:
                raise ValueError(f"JSON validation failed: {e.message}") from e

    return json.dumps(payload, indent=2, sort_keys=True)


def _transform_to_minimal(report: dict[str, Any]) -> dict[str, Any]:
    """Transform report to minimal format."""
    findings = report.get("findings", [])
    scores = report.get("scores", {})
    executive_summary = report.get("executive_summary", {})

    minimal_findings = []
    for finding in findings:
        minimal_findings.append(
            {
                "kind": finding.get("kind"),
                "target": finding.get("target"),
                "parameter": finding.get("parameter"),
                "severity": finding.get("severity"),
                "cvss": finding.get("cvss"),
                "confidence": finding.get("confidence"),
            }
        )

    return {
        "target": report.get("target"),
        "generated_at": report.get("generated_at"),
        "summary": {
            "total_findings": len(findings),
            "highest_severity": executive_summary.get("highest_severity"),
            "highest_cvss": scores.get("highest"),
            "average_cvss": scores.get("average"),
        },
        "findings": minimal_findings,
    }


def _transform_to_machine_readable(report: dict[str, Any]) -> dict[str, Any]:
    """Transform report to machine-readable format with arrays instead of nested objects."""
    findings = report.get("findings", [])
    scores = report.get("scores", {})
    executive_summary = report.get("executive_summary", {})
    compliance_summary = report.get("compliance", {})

    machine_findings = []
    for finding in findings:
        details = finding if isinstance(finding, dict) else {}
        compliance = (
            details.get("compliance", {}) if isinstance(details.get("compliance"), dict) else {}
        )

        # Extract compliance IDs as arrays
        cwe = compliance.get("cwe", {}) if isinstance(compliance.get("cwe"), dict) else {}
        owasp = (
            compliance.get("owasp_top_10", [])
            if isinstance(compliance.get("owasp_top_10"), list)
            else []
        )
        pci = (
            compliance.get("pci_dss_v4", [])
            if isinstance(compliance.get("pci_dss_v4"), list)
            else []
        )
        nist = (
            compliance.get("nist_800_53", [])
            if isinstance(compliance.get("nist_800_53"), list)
            else []
        )

        machine_findings.append(
            {
                "kind": details.get("kind"),
                "target": details.get("target"),
                "parameter": details.get("parameter"),
                "location": details.get("location"),
                "severity": details.get("severity"),
                "cvss": details.get("cvss"),
                "cvss_base": details.get("cvss_base"),
                "cvss_temporal": details.get("cvss_temporal"),
                "cvss_environmental": details.get("cvss_environmental"),
                "confidence": details.get("confidence"),
                "confidence_score": details.get("confidence_score"),
                "evidence_count": details.get("evidence_count"),
                "signals": details.get("signals", []),
                "observed_payloads": details.get("observed_payloads", []),
                "errors": details.get("errors", []),
                "cwe_ids": [cwe.get("id")] if cwe.get("id") else [],
                "owasp_ids": [item.get("id") for item in owasp if isinstance(item, dict)],
                "pci_dss_ids": [item.get("id") for item in pci if isinstance(item, dict)],
                "nist_ids": [item.get("id") for item in nist if isinstance(item, dict)],
                "remediation": details.get("remediation", []),
            }
        )

    # Count compliance categories
    severity_counts = scores.get("severity_counts", {})

    return {
        "scan_info": {
            "target": report.get("target"),
            "generated_at": report.get("generated_at"),
            "total_findings": len(findings),
            "risk_score": executive_summary.get("risk_score"),
            "risk_rating": executive_summary.get("risk_rating"),
            "highest_cvss": scores.get("highest"),
            "average_cvss": scores.get("average"),
        },
        "findings": machine_findings,
        "severity_counts": severity_counts,
        "compliance_summary": {
            "cwe_count": len(compliance_summary.get("cwe", [])),
            "owasp_count": len(compliance_summary.get("owasp_top_10", [])),
            "pci_dss_count": len(compliance_summary.get("pci_dss_v4", [])),
            "nist_count": len(compliance_summary.get("nist_800_53", [])),
        },
    }


def _filter_metadata(report: dict[str, Any]) -> dict[str, Any]:
    """Filter out metadata fields."""
    filtered = dict(report)
    filtered.pop("metadata", None)
    return filtered


def _filter_evidence(report: dict[str, Any]) -> dict[str, Any]:
    """Filter out evidence material from findings."""
    filtered = dict(report)
    findings = filtered.get("findings", [])
    for finding in findings:
        if isinstance(finding, dict):
            finding.pop("evidence_pairs", None)
            finding.pop("evidence_bundle", None)
            details = finding.get("details") if isinstance(finding.get("details"), dict) else None
            if details:
                details.pop("evidence_pairs", None)
                details.pop("evidence_bundle", None)
    return filtered


def _get_schema_path(format: str) -> Path:
    """Get path to JSON schema file for given format."""
    schema_dir = Path(__file__).parent / "schemas"
    if format == "minimal":
        return schema_dir / "minimal_schema.json"
    elif format == "machine_readable":
        return schema_dir / "machine_readable_schema.json"
    else:
        return schema_dir / "report_schema.json"


__all__ = [
    "render_json",
]
