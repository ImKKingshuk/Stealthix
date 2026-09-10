from __future__ import annotations

import defusedxml

defusedxml.defuse_stdlib()

from xml.etree.ElementTree import Element, SubElement, tostring  # noqa: E402

from stealthix.core.models import ScanResult  # noqa: E402
from stealthix.reporting.presentation import build_report_context  # noqa: E402


def render_junit(result: ScanResult) -> str:
    report = build_report_context(result)
    findings = report["findings"]
    root = Element("testsuites")
    suite = SubElement(
        root,
        "testsuite",
        {
            "name": "Stealthix Security Scan",
            "tests": str(max(1, len(findings))),
            "failures": str(len(findings)),
            "errors": "0",
            "time": "0",
        },
    )
    properties = SubElement(suite, "properties")
    for name, value in {
        "target": report["target"],
        "generated_at": report.get("generated_at") or "",
        "risk_score": str(report["executive_summary"]["risk_score"]),
        "highest_cvss": str(report["scores"]["highest"]),
    }.items():
        SubElement(properties, "property", {"name": name, "value": str(value)})

    if not findings:
        testcase = SubElement(
            suite, "testcase", {"classname": "stealthix.clean", "name": "No findings", "time": "0"}
        )
        system_out = SubElement(testcase, "system-out")
        system_out.text = "No security findings were recorded."
    for finding in findings:
        testcase = SubElement(
            suite,
            "testcase",
            {
                "classname": str(finding["kind"]),
                "name": str(finding["target"]),
                "time": "0",
            },
        )
        failure = SubElement(
            testcase,
            "failure",
            {
                "message": str(finding["summary"]),
                "type": str(finding["severity"]),
            },
        )
        failure.text = "\n".join(
            [
                f"CWE: {finding['compliance']['cwe']['id']} - {finding['compliance']['cwe']['name']}",
                f"OWASP: {', '.join(item['id'] for item in finding['compliance']['owasp_top_10'])}",
                f"CVSS base/temporal/environmental: {finding['cvss_base']} / {finding['cvss_temporal']} / {finding['cvss_environmental']}",
                *[f"Remediation: {item}" for item in finding["remediation"][:2]],
            ]
        )
        system_out = SubElement(testcase, "system-out")
        evidence = (
            finding["evidence_pairs"][0]
            if finding["evidence_pairs"]
            else {"request": {}, "response": {}}
        )
        system_out.text = "\n".join(
            [
                f"Request: {evidence['request'].get('method', '')} {evidence['request'].get('url', '')}".strip(),
                f"Response: {evidence['response'].get('status', '')} {evidence['response'].get('content_type', '')}".strip(),
                f"Evidence excerpt: {evidence['response'].get('body', '')}".strip(),
            ]
        )
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + tostring(root, encoding="unicode")


__all__ = ["render_junit"]
