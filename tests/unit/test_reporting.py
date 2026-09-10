from stealthix.core.engine import Finding, ScanResult
from stealthix.reporting import (
    render_csv,
    render_html,
    render_json,
    render_junit,
    render_markdown,
    render_pdf,
    render_sarif,
)


def test_renderers():
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-error",
                target="http://example.com?id=1",
                parameter="id",
                location="query",
                details={
                    "confidence": "high",
                    "confidence_score": 0.91,
                    "evidence_count": 2,
                    "signals": ["sql-error-signature"],
                    "observed_payloads": ["'", '"'],
                    "errors": ["SQLSTATE[42000] syntax error"],
                },
            )
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )
    html = render_html(result)
    json_output = render_json(result)
    markdown = render_markdown(result)
    pdf_output = render_pdf(result)
    sarif_output = render_sarif(result)
    junit_output = render_junit(result)
    csv_output = render_csv(result)
    assert "Stealthix Enterprise Report" in html
    assert '"target": "http://example.com"' in json_output
    assert '"confidence": "high"' in json_output
    assert "kind" in csv_output
    assert "sqli-error" in csv_output
    assert "## Findings" in markdown
    assert "confidence high (0.91)" in markdown
    assert "sql-error-signature" in html
    assert '"version": "2.1.0"' in sarif_output
    assert "<testsuite" in junit_output
    assert pdf_output.startswith(b"%PDF")
