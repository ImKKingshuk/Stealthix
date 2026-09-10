"""Unit tests for CSV report export."""

from __future__ import annotations

import pytest

from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.csv_report import AVAILABLE_COLUMNS, DEFAULT_COLUMNS, render_csv


def test_render_csv_default_columns() -> None:
    """Test CSV rendering with default columns."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={"cvss": 7.5, "confidence_score": 0.8, "confidence": "high"},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    csv = render_csv(result)

    assert isinstance(csv, str)
    assert "kind" in csv
    assert "severity" in csv
    assert "cvss" in csv
    assert "target" in csv
    assert "parameter" in csv
    assert "confidence" in csv
    assert "sqli-boolean" in csv
    assert "http://example.com" in csv


def test_render_csv_custom_columns() -> None:
    """Test CSV rendering with custom columns."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={"cvss": 7.5, "confidence_score": 0.8, "confidence": "high"},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    csv = render_csv(result, columns=["kind", "severity", "cvss"])

    assert isinstance(csv, str)
    assert "kind,severity,cvss" in csv
    assert "parameter" not in csv


def test_render_csv_no_header() -> None:
    """Test CSV rendering without header."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={"cvss": 7.5, "confidence_score": 0.8, "confidence": "high"},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    csv = render_csv(result, include_header=False)

    assert isinstance(csv, str)
    assert "kind" not in csv.split("\n")[0]  # First line should not be header
    assert "sqli-boolean" in csv


def test_render_csv_empty_findings() -> None:
    """Test CSV rendering with no findings."""
    result = ScanResult(
        target="http://example.com",
        findings=[],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    csv = render_csv(result)

    assert isinstance(csv, str)
    assert "kind" in csv  # Header should still be present


def test_render_csv_special_characters() -> None:
    """Test CSV rendering with special characters in values."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={
                    "cvss": 7.5,
                    "confidence_score": 0.8,
                    "confidence": "high",
                    "signals": ["sql-error", "timing-outlier;special"],
                },
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    csv = render_csv(result)

    assert isinstance(csv, str)
    assert "sql-error" in csv


def test_available_columns() -> None:
    """Test that AVAILABLE_COLUMNS includes all expected columns."""
    assert "kind" in AVAILABLE_COLUMNS
    assert "severity" in AVAILABLE_COLUMNS
    assert "cvss" in AVAILABLE_COLUMNS
    assert "target" in AVAILABLE_COLUMNS
    assert "parameter" in AVAILABLE_COLUMNS
    assert "confidence" in AVAILABLE_COLUMNS
    assert "cvss_base" in AVAILABLE_COLUMNS
    assert "cvss_temporal" in AVAILABLE_COLUMNS
    assert "cvss_environmental" in AVAILABLE_COLUMNS


def test_default_columns() -> None:
    """Test that DEFAULT_COLUMNS includes essential columns."""
    assert "kind" in DEFAULT_COLUMNS
    assert "severity" in DEFAULT_COLUMNS
    assert "cvss" in DEFAULT_COLUMNS
    assert "target" in DEFAULT_COLUMNS
    assert "confidence" in DEFAULT_COLUMNS
