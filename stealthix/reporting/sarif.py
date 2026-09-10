from __future__ import annotations

import hashlib
import json

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context


def _sarif_level(severity: str) -> str:
    lowered = severity.lower()
    if lowered in {"critical", "high"}:
        return "error"
    if lowered == "medium":
        return "warning"
    return "note"


def render_sarif(result: ScanResult) -> str:
    report = build_report_context(result)
    findings = report["findings"]
    rules: list[dict[str, object]] = []
    rule_indexes: dict[str, int] = {}
    for finding in findings:
        rule_id = str(finding["kind"])
        if rule_id in rule_indexes:
            continue
        rule_indexes[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding["compliance"]["title"]},
                "fullDescription": {"text": finding["summary"]},
                "help": {"text": " ".join(finding["remediation"])},
                "properties": {
                    "precision": str(finding["confidence"]),
                    "security-severity": str(finding["cvss"]),
                    "tags": [
                        finding["severity"],
                        finding["compliance"]["cwe"]["id"],
                        *[item["id"] for item in finding["compliance"]["owasp_top_10"]],
                    ],
                },
            }
        )

    results: list[dict[str, object]] = []
    for finding in findings:
        fingerprint = hashlib.sha256(
            f"{finding['kind']}|{finding['target']}|{finding.get('parameter') or ''}".encode()
        ).hexdigest()
        results.append(
            {
                "ruleId": str(finding["kind"]),
                "ruleIndex": rule_indexes[str(finding["kind"])],
                "level": _sarif_level(str(finding["severity"])),
                "message": {"text": str(finding["summary"])},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(finding["target"]),
                                "uriBaseId": "%SRCROOT%",
                            },
                        }
                    }
                ],
                "partialFingerprints": {"stealthixPrimaryFingerprint": fingerprint},
                "properties": {
                    "parameter": finding.get("parameter"),
                    "location": finding.get("location"),
                    "cvss": finding["cvss"],
                    "cvssBase": finding["cvss_base"],
                    "cvssTemporal": finding["cvss_temporal"],
                    "cvssEnvironmental": finding["cvss_environmental"],
                    "severity": finding["severity"],
                    "confidence": finding["confidence"],
                    "cwe": finding["compliance"]["cwe"]["id"],
                    "owaspTop10": [item["id"] for item in finding["compliance"]["owasp_top_10"]],
                    "pciDss": [item["id"] for item in finding["compliance"]["pci_dss_v4"]],
                    "nist80053": [item["id"] for item in finding["compliance"]["nist_800_53"]],
                },
            }
        )

    payload = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Stealthix",
                        "informationUri": "https://github.com",
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": "stealthix.enterprise-report"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolConfigurationNotifications": [],
                        "properties": {
                            "target": report["target"],
                            "generatedAt": report.get("generated_at"),
                        },
                    }
                ],
                "results": results,
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)


__all__ = ["render_sarif"]
