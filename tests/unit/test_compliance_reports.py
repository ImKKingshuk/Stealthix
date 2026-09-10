import json
from xml.etree import ElementTree as ET

from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.compliance import compliance_for_finding, summarize_compliance
from stealthix.reporting.junit import render_junit
from stealthix.reporting.presentation import build_report_context
from stealthix.reporting.sarif import render_sarif
from stealthix.reporting.scoring import score_cvss_breakdown, score_result


def _sample_result() -> ScanResult:
    return ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-error",
                target="http://example.com/search?id=1",
                parameter="id",
                location="query",
                details={
                    "confidence": "high",
                    "confidence_score": 0.96,
                    "signals": ["sql syntax error", "database exception"],
                    "errors": ["SQLSTATE[42000]"],
                    "cvss_metrics": {
                        "AV": "N",
                        "AC": "L",
                        "PR": "N",
                        "UI": "N",
                        "S": "C",
                        "C": "H",
                        "I": "H",
                        "A": "H",
                    },
                    "cvss_temporal_metrics": {"E": "F", "RL": "O", "RC": "C"},
                    "cvss_environmental_metrics": {
                        "CR": "H",
                        "IR": "H",
                        "AR": "M",
                        "MC": "H",
                        "MI": "H",
                        "MA": "L",
                    },
                },
            ),
            Finding(
                kind="idor",
                target="http://example.com/api/users/42",
                details={"confidence": "medium", "signals": ["foreign object access"]},
            ),
        ],
        metadata={
            "generated_at": "2026-03-11T12:00:00+00:00",
            "auth": {
                "authenticated": True,
                "auth_type": "form",
                "authenticated_at": "2026-03-11T11:58:00+00:00",
            },
            "request_history": [
                {
                    "url": "http://example.com/search?id=1",
                    "method": "GET",
                    "status": "500",
                    "timestamp": "2026-03-11T11:59:00+00:00",
                    "metadata": {
                        "request_headers": {"Authorization": "Bearer redacted"},
                        "request_body": "id=1'",
                        "response_excerpt": "SQLSTATE[42000] syntax error near '1''",
                        "content_type": "text/html",
                    },
                }
            ],
            "crawl": {"target_count": 2, "page_count": 4},
            "scanned_targets": [
                "http://example.com/search?id=1",
                "http://example.com/api/users/42",
            ],
        },
    )


def test_compliance_mapping_and_summary_cover_enterprise_taxonomies():
    result = _sample_result()

    first = compliance_for_finding(result.findings[0])
    summary = summarize_compliance(result.findings)

    assert first["cwe"]["id"] == "CWE-89"
    assert first["owasp_top_10"][0]["id"] == "A03:2021"
    assert any(item["id"] == "6.5.1" for item in first["pci_dss_v4"])
    assert any(item["id"] == "CWE-639" for item in summary["cwe"])


def test_cvss_breakdown_supports_temporal_and_environmental_metrics():
    breakdown = score_cvss_breakdown(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
        temporal_metrics={"E": "F", "RL": "O", "RC": "C"},
        environmental_metrics={"CR": "H", "IR": "H", "AR": "M", "MC": "H", "MI": "H", "MA": "L"},
    )

    assert breakdown["base"] >= 9.0
    assert breakdown["temporal"] <= breakdown["base"]
    assert breakdown["environmental"] > 0
    assert breakdown["severity"] in {"Critical", "High"}


def test_report_context_includes_executive_summary_evidence_and_timeline():
    report = build_report_context(_sample_result())

    assert report["executive_summary"]["risk_score"] > 0
    assert report["findings"][0]["evidence_pairs"][0]["response"]["body"].startswith("SQLSTATE")
    assert any(event["phase"] == "Authentication" for event in report["timeline"])
    assert report["attack_surface"]["request_count"] == 1


def test_sarif_and_junit_exports_include_compliance_metadata():
    result = _sample_result()

    sarif = json.loads(render_sarif(result))
    junit = render_junit(result)
    xml_root = ET.fromstring(junit)

    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["properties"]["cwe"] == "CWE-89"
    assert sarif["runs"][0]["results"][0]["level"] in {"error", "warning", "note"}
    testcase = xml_root.find("./testsuite/testcase")
    assert testcase is not None
    assert testcase.find("failure") is not None
    assert "CWE: CWE-89" in (testcase.find("failure").text or "")


def test_score_result_reports_risk_index_and_severity_counts():
    scores = score_result(_sample_result())

    assert scores["risk_index"] > 0
    assert scores["severity_counts"]["Critical"] + scores["severity_counts"]["High"] >= 1
