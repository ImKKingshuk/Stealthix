"""Unit tests for enhanced HTML report features."""

from __future__ import annotations

import pytest

from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.html import _generate_chart_data, render_html


def test_generate_chart_data_severity_distribution() -> None:
    """Test severity distribution chart data generation."""
    report = {
        "findings": [
            {"severity": "Critical", "kind": "sqli-union"},
            {"severity": "High", "kind": "sqli-boolean"},
            {"severity": "High", "kind": "sqli-time"},
            {"severity": "Medium", "kind": "nosqli-mongodb"},
            {"severity": "Low", "kind": "idor"},
        ],
        "compliance": {},
    }

    chart_data = _generate_chart_data(report)

    assert "severity" in chart_data
    assert chart_data["severity"]["labels"] == ["Critical", "High", "Medium", "Low", "Info"]
    assert chart_data["severity"]["data"] == [1, 2, 1, 1, 0]


def test_generate_chart_data_kind_distribution() -> None:
    """Test findings by kind chart data generation."""
    report = {
        "findings": [
            {"severity": "Critical", "kind": "sqli-union"},
            {"severity": "High", "kind": "sqli-boolean"},
            {"severity": "High", "kind": "sqli-boolean"},
            {"severity": "Medium", "kind": "nosqli-mongodb"},
        ],
        "compliance": {},
    }

    chart_data = _generate_chart_data(report)

    assert "kind" in chart_data
    assert "sqli-boolean" in chart_data["kind"]["labels"]
    assert chart_data["kind"]["data"][chart_data["kind"]["labels"].index("sqli-boolean")] == 2


def test_generate_chart_data_compliance_mapping() -> None:
    """Test compliance mapping chart data generation."""
    report = {
        "findings": [],
        "compliance": {
            "owasp_top_10": {
                "A03:2021": {"id": "A03:2021", "count": 5},
                "A01:2021": {"id": "A01:2021", "count": 3},
            },
            "pci_dss_v4": {
                "6.5.1": {"id": "6.5.1", "count": 4},
            },
            "nist_800_53": {},
        },
    }

    chart_data = _generate_chart_data(report)

    assert "compliance" in chart_data
    assert len(chart_data["compliance"]["datasets"]) == 3  # OWASP, PCI, NIST
    assert chart_data["compliance"]["datasets"][0]["label"] == "OWASP"


def test_generate_chart_data_cvss_distribution() -> None:
    """Test CVSS distribution chart data generation."""
    report = {
        "findings": [
            {"severity": "Critical", "kind": "sqli-union", "cvss": 9.5},
            {"severity": "High", "kind": "sqli-boolean", "cvss": 7.5},
            {"severity": "Medium", "kind": "nosqli-mongodb", "cvss": 5.0},
            {"severity": "Low", "kind": "idor", "cvss": 3.0},
        ],
        "compliance": {},
    }

    chart_data = _generate_chart_data(report)

    assert "cvss" in chart_data
    assert chart_data["cvss"]["labels"] == ["0-2", "2-4", "4-6", "6-8", "8-10"]
    assert chart_data["cvss"]["data"] == [0, 1, 1, 1, 1]  # One in each bin except 0-2


def test_generate_chart_data_empty_findings() -> None:
    """Test chart data generation with no findings."""
    report = {
        "findings": [],
        "compliance": {},
    }

    chart_data = _generate_chart_data(report)

    assert "severity" in chart_data
    assert chart_data["severity"]["data"] == [0, 0, 0, 0, 0]
    assert "kind" in chart_data
    assert chart_data["kind"]["data"] == []


def test_generate_chart_data_no_cvss_scores() -> None:
    """Test CVSS distribution with findings that have no CVSS scores."""
    report = {
        "findings": [
            {"severity": "Critical", "kind": "sqli-union", "cvss": 0},
            {"severity": "High", "kind": "sqli-boolean"},
        ],
        "compliance": {},
    }

    chart_data = _generate_chart_data(report)

    assert "cvss" in chart_data
    assert chart_data["cvss"]["data"] == [0, 0, 0, 0, 0]


def test_render_html_with_template() -> None:
    """Test HTML rendering with template."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                details={"cvss": 7.5, "confidence_score": 0.8},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    html = render_html(result)

    assert isinstance(html, str)
    assert len(html) > 0
    assert "Stealthix Enterprise Report" in html
    assert "http://example.com" in html


def test_render_html_includes_chart_data() -> None:
    """Test that rendered HTML includes chart data."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                details={"cvss": 7.5, "confidence_score": 0.8},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    html = render_html(result)

    assert "charts" in html.lower()
    assert "severity" in html.lower() or "chart" in html.lower()


def test_render_html_with_multiple_findings() -> None:
    """Test HTML rendering with multiple findings."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={"cvss": 7.5, "confidence_score": 0.8},
            ),
            Finding(
                kind="sqli-union",
                target="http://example.com",
                parameter="name",
                details={"cvss": 9.0, "confidence_score": 0.95},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    html = render_html(result)

    assert "sqli-boolean" in html
    assert "sqli-union" in html


def test_render_html_empty_findings() -> None:
    """Test HTML rendering with no findings."""
    result = ScanResult(
        target="http://example.com",
        findings=[],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    html = render_html(result)

    assert isinstance(html, str)
    assert len(html) > 0
