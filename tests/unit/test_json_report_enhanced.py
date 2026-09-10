"""Unit tests for enhanced JSON report features."""

from __future__ import annotations

import json

import pytest

from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.json_report import (
    _filter_evidence,
    _filter_metadata,
    _get_schema_path,
    _transform_to_machine_readable,
    _transform_to_minimal,
    render_json,
)


def test_render_json_default_format() -> None:
    """Test JSON rendering with default detailed format."""
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

    json_output = render_json(result, format="detailed")

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert data["target"] == "http://example.com"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["kind"] == "sqli-boolean"


def test_render_json_minimal_format() -> None:
    """Test JSON rendering with minimal format."""
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

    json_output = render_json(result, format="minimal")

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert data["target"] == "http://example.com"
    assert "summary" in data
    assert "findings" in data
    assert data["findings"][0]["kind"] == "sqli-boolean"
    # Minimal format should not have full details
    assert "scores" not in data
    assert "compliance" not in data


def test_render_json_machine_readable_format() -> None:
    """Test JSON rendering with machine-readable format."""
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

    json_output = render_json(result, format="machine_readable")

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert "scan_info" in data
    assert "findings" in data
    assert data["scan_info"]["target"] == "http://example.com"
    # Machine-readable should have arrays instead of nested objects
    assert "cwe_ids" in data["findings"][0]
    assert isinstance(data["findings"][0]["cwe_ids"], list)


def test_render_json_filter_metadata() -> None:
    """Test JSON rendering with metadata filtering."""
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
        metadata={"generated_at": "2024-01-01T00:00:00Z", "custom_field": "value"},
    )

    json_output = render_json(result, include_metadata=False)

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert "metadata" not in data


def test_render_json_filter_timeline() -> None:
    """Test JSON rendering with timeline filtering."""
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

    json_output = render_json(result, include_timeline=False)

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert "timeline" not in data


def test_render_json_filter_recon() -> None:
    """Test JSON rendering with reconnaissance filtering."""
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

    json_output = render_json(result, include_recon=False)

    assert isinstance(json_output, str)
    data = json.loads(json_output)
    assert "reconnaissance" not in data


def test_transform_to_minimal() -> None:
    """Test _transform_to_minimal function."""
    report = {
        "target": "http://example.com",
        "generated_at": "2024-01-01T00:00:00Z",
        "findings": [
            {
                "kind": "sqli-boolean",
                "target": "http://example.com",
                "parameter": "id",
                "severity": "High",
                "cvss": 7.5,
                "confidence": "high",
            }
        ],
        "scores": {"highest": 7.5, "average": 7.5},
        "executive_summary": {"highest_severity": "High"},
    }

    minimal = _transform_to_minimal(report)

    assert minimal["target"] == "http://example.com"
    assert "summary" in minimal
    assert "findings" in minimal
    assert minimal["findings"][0]["kind"] == "sqli-boolean"
    assert "scores" not in minimal


def test_transform_to_machine_readable() -> None:
    """Test _transform_to_machine_readable function."""
    report = {
        "target": "http://example.com",
        "generated_at": "2024-01-01T00:00:00Z",
        "findings": [
            {
                "kind": "sqli-boolean",
                "target": "http://example.com",
                "parameter": "id",
                "severity": "High",
                "cvss": 7.5,
                "confidence": "high",
                "compliance": {
                    "cwe": {"id": "CWE-89", "name": "SQL Injection"},
                    "owasp_top_10": [{"id": "A03:2021", "name": "Injection"}],
                },
            }
        ],
        "scores": {"highest": 7.5, "average": 7.5},
        "executive_summary": {"risk_score": 75, "risk_rating": "High"},
    }

    machine_readable = _transform_to_machine_readable(report)

    assert "scan_info" in machine_readable
    assert "findings" in machine_readable
    assert machine_readable["scan_info"]["target"] == "http://example.com"
    assert "cwe_ids" in machine_readable["findings"][0]
    assert machine_readable["findings"][0]["cwe_ids"] == ["CWE-89"]
    assert "owasp_ids" in machine_readable["findings"][0]
    assert machine_readable["findings"][0]["owasp_ids"] == ["A03:2021"]


def test_filter_metadata() -> None:
    """Test _filter_metadata function."""
    report = {"target": "http://example.com", "metadata": {"custom": "value"}}

    filtered = _filter_metadata(report)

    assert "metadata" not in filtered
    assert "target" in filtered


def test_filter_evidence() -> None:
    """Test _filter_evidence function."""
    report = {
        "findings": [{"kind": "sqli-boolean", "evidence_pairs": [{"request": {}, "response": {}}]}]
    }

    filtered = _filter_evidence(report)

    assert "evidence_pairs" not in filtered["findings"][0]
    assert "kind" in filtered["findings"][0]


def test_get_schema_path() -> None:
    """Test _get_schema_path function."""
    detailed_path = _get_schema_path("detailed")
    minimal_path = _get_schema_path("minimal")
    machine_readable_path = _get_schema_path("machine_readable")

    assert "report_schema.json" in str(detailed_path)
    assert "minimal_schema.json" in str(minimal_path)
    assert "machine_readable_schema.json" in str(machine_readable_path)


def test_render_json_validate_without_jsonschema() -> None:
    """Test JSON validation with valid data."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                location="query",
                details={"cvss": 7.5, "confidence_score": 0.8, "confidence": "high"},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    # Should validate successfully with valid data
    json_output = render_json(result, validate_schema=True)

    assert isinstance(json_output, str)
