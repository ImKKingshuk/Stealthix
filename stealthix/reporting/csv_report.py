"""CSV report export for Stealthix findings."""

from __future__ import annotations

import csv
from io import StringIO
from typing import Any

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context

# Default columns for CSV export
DEFAULT_COLUMNS = [
    "kind",
    "severity",
    "cvss",
    "target",
    "parameter",
    "location",
    "confidence",
    "confidence_score",
    "evidence_count",
    "signals",
    "observed_payloads",
    "errors",
    "compliance_cwe_id",
    "compliance_owasp_ids",
    "remediation",
]

# All available columns
AVAILABLE_COLUMNS = DEFAULT_COLUMNS + [
    "cvss_base",
    "cvss_temporal",
    "cvss_environmental",
]


def render_csv(
    result: ScanResult,
    columns: list[str] | None = None,
    include_header: bool = True,
) -> str:
    """
    Render findings as CSV.

    Args:
        result: ScanResult to export
        columns: List of columns to include (default: DEFAULT_COLUMNS)
        include_header: Whether to include header row

    Returns:
        CSV string
    """
    if columns is None:
        columns = DEFAULT_COLUMNS

    report = build_report_context(result)
    findings = report.get("findings", [])

    output = StringIO()
    writer = csv.writer(output)

    if include_header:
        writer.writerow(columns)

    for finding in findings:
        row = [_get_column_value(finding, col) for col in columns]
        writer.writerow(row)

    return output.getvalue()


def _get_column_value(finding: dict[str, Any], column: str) -> str:
    """Get the value for a specific column from a finding.

    Args:
        finding: Finding dictionary
        column: Column name

    Returns:
        String value for the column
    """
    details = finding if isinstance(finding, dict) else {}
    compliance = (
        details.get("compliance", {}) if isinstance(details.get("compliance"), dict) else {}
    )

    if column == "kind":
        return str(details.get("kind", "") or "")
    elif column == "severity":
        return str(details.get("severity", "") or "")
    elif column == "cvss":
        return str(details.get("cvss", 0.0) or 0.0)
    elif column == "cvss_base":
        return str(details.get("cvss_base", 0.0) or 0.0)
    elif column == "cvss_temporal":
        return str(details.get("cvss_temporal", 0.0) or 0.0)
    elif column == "cvss_environmental":
        return str(details.get("cvss_environmental", 0.0) or 0.0)
    elif column == "target":
        return str(details.get("target", "") or "")
    elif column == "parameter":
        return str(details.get("parameter", "") or "")
    elif column == "location":
        return str(details.get("location", "") or "")
    elif column == "confidence":
        return str(details.get("confidence", "") or "")
    elif column == "confidence_score":
        return str(details.get("confidence_score", 0.0) or 0.0)
    elif column == "evidence_count":
        return str(details.get("evidence_count", 1) or 1)
    elif column == "signals":
        signals = details.get("signals", []) if isinstance(details.get("signals"), list) else []
        return "; ".join(str(s) for s in signals)
    elif column == "observed_payloads":
        payloads = (
            details.get("observed_payloads", [])
            if isinstance(details.get("observed_payloads"), list)
            else []
        )
        return "; ".join(str(p) for p in payloads)
    elif column == "errors":
        errors = details.get("errors", []) if isinstance(details.get("errors"), list) else []
        return "; ".join(str(e) for e in errors)
    elif column == "compliance_cwe_id":
        cwe = compliance.get("cwe", {}) if isinstance(compliance.get("cwe"), dict) else {}
        return str(cwe.get("id", "") or "")
    elif column == "compliance_owasp_ids":
        owasp = (
            compliance.get("owasp_top_10", [])
            if isinstance(compliance.get("owasp_top_10"), list)
            else []
        )
        return "; ".join(str(item.get("id", "")) for item in owasp if isinstance(item, dict))
    elif column == "remediation":
        remediation = (
            details.get("remediation", []) if isinstance(details.get("remediation"), list) else []
        )
        return str(remediation[0] if remediation else "")
    else:
        return ""


__all__ = [
    "render_csv",
    "DEFAULT_COLUMNS",
    "AVAILABLE_COLUMNS",
]
