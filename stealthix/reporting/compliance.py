from __future__ import annotations

from typing import Any

from stealthix.core.models import Finding


def _catalog() -> dict[str, dict[str, Any]]:
    return {
        "sql-injection": {
            "title": "SQL Injection",
            "cwe": {
                "id": "CWE-89",
                "name": "Improper Neutralization of Special Elements used in an SQL Command",
            },
            "owasp_top_10": [{"id": "A03:2021", "name": "Injection"}],
            "pci_dss_v4": [
                {
                    "id": "6.5.1",
                    "name": "Injection flaws",
                    "requirement": "Protect public-facing applications against injection attacks.",
                }
            ],
            "sans_top_25": [
                {
                    "id": "CWE-89",
                    "name": "SQL Injection",
                    "category": "Insecure Interaction Between Components",
                }
            ],
            "nist_800_53": [
                {"id": "SI-10", "name": "Information Input Validation"},
                {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning"},
                {"id": "SA-11", "name": "Developer Testing and Evaluation"},
            ],
            "remediation": [
                "Use parameterized queries or prepared statements for every database interaction.",
                "Enforce strict server-side input validation and type constraints before query construction.",
                "Avoid dynamic SQL concatenation in application and stored procedure code paths.",
                "Apply least-privilege database credentials and monitor anomalous query behavior.",
            ],
        },
        "nosql-injection": {
            "title": "NoSQL / Query Logic Injection",
            "cwe": {
                "id": "CWE-943",
                "name": "Improper Neutralization of Special Elements in Data Query Logic",
            },
            "owasp_top_10": [{"id": "A03:2021", "name": "Injection"}],
            "pci_dss_v4": [
                {
                    "id": "6.5.1",
                    "name": "Injection flaws",
                    "requirement": "Protect public-facing applications against injection attacks.",
                }
            ],
            "sans_top_25": [
                {
                    "id": "CWE-943",
                    "name": "Improper Neutralization in Query Logic",
                    "category": "Insecure Interaction Between Components",
                }
            ],
            "nist_800_53": [
                {"id": "SI-10", "name": "Information Input Validation"},
                {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning"},
                {"id": "SA-11", "name": "Developer Testing and Evaluation"},
            ],
            "remediation": [
                "Use typed query builders and explicit allowlists for operators such as $ne, $gt, or map-based predicates.",
                "Normalize and validate nested JSON/body structures before they reach query execution layers.",
                "Disallow direct user control over query selectors, sort expressions, and filter operators.",
                "Run database accounts with least privilege and alert on suspicious query-shape changes.",
            ],
        },
        "broken-access-control": {
            "title": "Broken Access Control / IDOR",
            "cwe": {"id": "CWE-639", "name": "Authorization Bypass Through User-Controlled Key"},
            "owasp_top_10": [{"id": "A01:2021", "name": "Broken Access Control"}],
            "pci_dss_v4": [
                {
                    "id": "7.2.5",
                    "name": "Access control enforcement",
                    "requirement": "Restrict access to system components and data by business need to know.",
                }
            ],
            "sans_top_25": [
                {
                    "id": "CWE-639",
                    "name": "Authorization Bypass Through User-Controlled Key",
                    "category": "Improper Access Control",
                }
            ],
            "nist_800_53": [
                {"id": "AC-3", "name": "Access Enforcement"},
                {"id": "AC-6", "name": "Least Privilege"},
                {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning"},
            ],
            "remediation": [
                "Enforce object-level authorization on every resource lookup, not just at the UI layer.",
                "Use opaque identifiers where possible and validate tenant/user ownership server side.",
                "Add negative authorization tests to CI for cross-account record access and mass assignment paths.",
            ],
        },
        "generic": {
            "title": "Security Finding",
            "cwe": {"id": "CWE-20", "name": "Improper Input Validation"},
            "owasp_top_10": [{"id": "A03:2021", "name": "Injection"}],
            "pci_dss_v4": [
                {
                    "id": "6.2.4",
                    "name": "Secure coding practices",
                    "requirement": "Address common software coding vulnerabilities using secure coding techniques.",
                }
            ],
            "sans_top_25": [
                {
                    "id": "CWE-20",
                    "name": "Improper Input Validation",
                    "category": "Insecure Interaction Between Components",
                }
            ],
            "nist_800_53": [
                {"id": "SI-10", "name": "Information Input Validation"},
                {"id": "RA-5", "name": "Vulnerability Monitoring and Scanning"},
            ],
            "remediation": [
                "Validate and normalize user-controlled input before it reaches sensitive execution paths.",
                "Instrument the affected code path with defensive logging and add regression tests for the discovered behavior.",
            ],
        },
    }


def _family_for_kind(kind: str) -> str:
    lowered = kind.lower()
    if (
        lowered.startswith("sqli")
        or lowered.startswith("newsql")
        or lowered.startswith("timeseriesqli")
    ):
        return "sql-injection"
    if (
        lowered.startswith("nosqli")
        or lowered.startswith("graphqli")
        or lowered.startswith("searchqli")
    ):
        return "nosql-injection"
    if lowered.startswith("websocket-"):
        suffix = lowered.removeprefix("websocket-")
        return _family_for_kind(suffix)
    if lowered == "idor":
        return "broken-access-control"
    return "generic"


def compliance_for_finding(finding: Finding) -> dict[str, Any]:
    family = _family_for_kind(finding.kind)
    item = _catalog()[family]
    return {
        "family": family,
        "title": item["title"],
        "cwe": dict(item["cwe"]),
        "owasp_top_10": [dict(value) for value in item["owasp_top_10"]],
        "pci_dss_v4": [dict(value) for value in item["pci_dss_v4"]],
        "sans_top_25": [dict(value) for value in item["sans_top_25"]],
        "nist_800_53": [dict(value) for value in item["nist_800_53"]],
        "remediation": list(item["remediation"]),
    }


def summarize_compliance(findings: list[Finding]) -> dict[str, Any]:
    summary = {
        "owasp_top_10": {},
        "cwe": {},
        "pci_dss_v4": {},
        "sans_top_25": {},
        "nist_800_53": {},
    }
    for finding in findings:
        mapped = compliance_for_finding(finding)
        for entry in mapped["owasp_top_10"]:
            summary["owasp_top_10"].setdefault(entry["id"], {**entry, "count": 0})["count"] += 1
        cwe = mapped["cwe"]
        summary["cwe"].setdefault(cwe["id"], {**cwe, "count": 0})["count"] += 1
        for entry in mapped["pci_dss_v4"]:
            summary["pci_dss_v4"].setdefault(entry["id"], {**entry, "count": 0})["count"] += 1
        for entry in mapped["sans_top_25"]:
            summary["sans_top_25"].setdefault(entry["id"], {**entry, "count": 0})["count"] += 1
        for entry in mapped["nist_800_53"]:
            summary["nist_800_53"].setdefault(entry["id"], {**entry, "count": 0})["count"] += 1
    return {
        key: sorted(value.values(), key=lambda item: (-int(item["count"]), str(item["id"])))
        for key, value in summary.items()
    }


__all__ = ["compliance_for_finding", "summarize_compliance"]
