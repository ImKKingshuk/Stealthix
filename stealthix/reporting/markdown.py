from __future__ import annotations

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context


def render_markdown(result: ScanResult) -> str:
    report = build_report_context(result)
    scores = report["scores"]
    summary = report["executive_summary"]
    lines = [
        "# Stealthix Enterprise Report",
        f"Target: {result.target}",
        f"Generated: {report.get('generated_at') or ''}",
        f"Risk score: {summary['risk_score']} ({summary['risk_rating']})",
        f"Highest CVSS: {scores['highest']}",
        f"Average CVSS: {scores['average']}",
        f"CVSS base/temporal/environmental high: {scores['base_highest']} / {scores['temporal_highest']} / {scores['environmental_highest']}",
        "",
        "## Executive Summary",
        f"- Total findings: {summary['total_findings']}",
        f"- Highest severity: {summary['highest_severity']}",
        f"- Requests observed: {report['attack_surface']['request_count']}",
        f"- Targets observed: {report['attack_surface']['target_count']}",
        "",
        "## Compliance Mapping",
        f"- OWASP Top 10: {', '.join(item['id'] for item in report['compliance']['owasp_top_10']) or 'None'}",
        f"- CWE: {', '.join(item['id'] for item in report['compliance']['cwe']) or 'None'}",
        f"- PCI DSS v4.0: {', '.join(item['id'] for item in report['compliance']['pci_dss_v4']) or 'None'}",
        f"- NIST 800-53: {', '.join(item['id'] for item in report['compliance']['nist_800_53']) or 'None'}",
        "",
        "## Findings",
    ]
    if not report["findings"]:
        lines.append("No findings.")
    for view in report["findings"]:
        lines.append(f"- **{view['kind']}** — {view['summary']}")
        lines.append(f"  - Target: `{view['target']}`")
        lines.append(f"  - Severity: {view['severity']}")
        lines.append(
            f"  - CVSS base/temporal/environmental: {view['cvss_base']} / {view['cvss_temporal']} / {view['cvss_environmental']}"
        )
        lines.append(
            f"  - CWE: {view['compliance']['cwe']['id']} ({view['compliance']['cwe']['name']})"
        )
        lines.append(
            f"  - OWASP: {', '.join(item['id'] for item in view['compliance']['owasp_top_10'])}"
        )
        if view["signals"]:
            lines.append(f"  - Signals: {', '.join(view['signals'][:5])}")
        if view["observed_payloads"]:
            lines.append(f"  - Payloads: {', '.join(view['observed_payloads'][:3])}")
        if view["errors"]:
            lines.append(f"  - Errors: {', '.join(view['errors'][:3])}")
        if view["remediation"]:
            lines.append(f"  - Remediation: {view['remediation'][0]}")
        if view["evidence_pairs"]:
            pair = view["evidence_pairs"][0]
            lines.append(
                f"  - Evidence request: {pair['request'].get('method')} {pair['request'].get('url')}"
            )
            if pair["response"].get("status"):
                lines.append(
                    f"  - Evidence response: {pair['response'].get('status')} {pair['response'].get('content_type') or ''}".rstrip()
                )
    lines.extend(["", "## Timeline"])
    if not report["timeline"]:
        lines.append("No timeline metadata captured.")
    for event in report["timeline"]:
        lines.append(f"- {event.get('timestamp') or ''} — {event['phase']}: {event['message']}")
    return "\n".join(lines)
