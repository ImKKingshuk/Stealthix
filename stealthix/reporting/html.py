from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, Template

from stealthix.core.models import ScanResult
from stealthix.reporting.presentation import build_report_context


def _generate_chart_data(report: dict[str, Any]) -> dict[str, Any]:
    """Generate chart data for interactive HTML reports.

    Args:
        report: Report context from build_report_context

    Returns:
        Dictionary containing chart data structures
    """
    findings = report.get("findings", [])

    # Severity distribution
    severity_counts = Counter(f.get("severity", "Info") for f in findings)
    severity_data = {
        "labels": ["Critical", "High", "Medium", "Low", "Info"],
        "data": [
            severity_counts.get("Critical", 0),
            severity_counts.get("High", 0),
            severity_counts.get("Medium", 0),
            severity_counts.get("Low", 0),
            severity_counts.get("Info", 0),
        ],
    }

    # Findings by kind
    kind_counts = Counter(f.get("kind", "unknown") for f in findings)
    kind_labels = list(kind_counts.keys())[:10]  # Top 10
    kind_data = {
        "labels": kind_labels,
        "data": [kind_counts[k] for k in kind_labels],
    }

    # Compliance mapping
    compliance_summary = report.get("compliance", {})
    owasp_data = compliance_summary.get("owasp_top_10", [])
    pci_data = compliance_summary.get("pci_dss_v4", [])
    nist_data = compliance_summary.get("nist_800_53", [])

    # Get top compliance categories
    all_compliance = {}
    for item in owasp_data if isinstance(owasp_data, list) else owasp_data.values():
        all_compliance[item["id"]] = all_compliance.get(item["id"], 0) + item["count"]
    for item in pci_data if isinstance(pci_data, list) else pci_data.values():
        all_compliance[item["id"]] = all_compliance.get(item["id"], 0) + item["count"]
    for item in nist_data if isinstance(nist_data, list) else nist_data.values():
        all_compliance[item["id"]] = all_compliance.get(item["id"], 0) + item["count"]

    top_compliance = sorted(all_compliance.items(), key=lambda x: x[1], reverse=True)[:5]

    # Helper to get count from list or dict
    def get_count(data, key):
        if isinstance(data, list):
            for item in data:
                if item.get("id") == key:
                    return item.get("count", 0)
        elif isinstance(data, dict):
            return data.get(key, {"count": 0}).get("count", 0)
        return 0

    compliance_data = {
        "labels": [item[0] for item in top_compliance],
        "datasets": [
            {
                "label": "OWASP",
                "data": [get_count(owasp_data, item[0]) for item in top_compliance],
            },
            {
                "label": "PCI DSS",
                "data": [get_count(pci_data, item[0]) for item in top_compliance],
            },
            {
                "label": "NIST",
                "data": [get_count(nist_data, item[0]) for item in top_compliance],
            },
        ],
    }

    # CVSS distribution
    cvss_scores = [f.get("cvss", 0) for f in findings if f.get("cvss", 0) > 0]
    cvss_bins = [0, 2, 4, 6, 8, 10]
    cvss_histogram = [0] * (len(cvss_bins) - 1)
    for score in cvss_scores:
        for i in range(len(cvss_bins) - 1):
            if cvss_bins[i] <= score < cvss_bins[i + 1]:
                cvss_histogram[i] += 1
                break

    cvss_data = {
        "labels": ["0-2", "2-4", "4-6", "6-8", "8-10"],
        "data": cvss_histogram,
    }

    return {
        "severity": severity_data,
        "kind": kind_data,
        "compliance": compliance_data,
        "cvss": cvss_data,
    }


def render_html(result: ScanResult) -> str:
    base = Path(__file__).resolve().parent / "templates"
    report = build_report_context(result)
    chart_data = _generate_chart_data(report)

    # Add chart data to report
    report["charts"] = chart_data

    if base.exists():
        env = Environment(loader=FileSystemLoader(str(base)), autoescape=True)
        template = env.get_template("report.html")
        return template.render(report=report)

    # Fallback template if templates directory doesn't exist
    template = Template(
        """
<html>
<head><title>Stealthix Report</title></head>
<body>
<h1>Stealthix Enterprise Report</h1>
<p>Target: {{ report.target }}</p>
<p>Generated: {{ report.generated_at }}</p>
<p>Risk Score: {{ report.executive_summary.risk_score }} ({{ report.executive_summary.risk_rating }})</p>
<p>Highest CVSS: {{ report.scores.highest }}</p>
<h2>Findings</h2>
<ul>
{% for finding in report.findings %}
  <li>
    <strong>{{ finding.kind }}</strong> — {{ finding.summary }}<br/>
    <span>{{ finding.target }}</span>
    {% if finding.signals %}
    <div>Signals: {{ finding.signals | join(", ") }}</div>
    {% endif %}
    {% if finding.errors %}
    <div>Errors: {{ finding.errors | join(", ") }}</div>
    {% endif %}
    <div>CWE: {{ finding.compliance.cwe.id }}</div>
  </li>
{% endfor %}
</ul>
</body>
</html>
""".strip()
    )
    return template.render(report=report)
