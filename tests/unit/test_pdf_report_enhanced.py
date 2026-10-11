"""Unit tests for enhanced PDF report features."""

from __future__ import annotations

import pytest

from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.pdf import _get_severity_color, render_pdf


def test_render_pdf_basic() -> None:
    """Test PDF rendering with basic scan result."""
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

    pdf_bytes = render_pdf(result)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_render_pdf_empty_findings() -> None:
    """Test PDF rendering with no findings."""
    result = ScanResult(
        target="http://example.com",
        findings=[],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    pdf_bytes = render_pdf(result)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_render_pdf_multiple_findings() -> None:
    """Test PDF rendering with multiple findings."""
    result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(
                kind="sqli-boolean",
                target="http://example.com",
                parameter="id",
                details={"cvss": 7.5, "confidence_score": 0.8, "confidence": "high"},
            ),
            Finding(
                kind="nosqli-mongodb",
                target="http://example.com",
                parameter="user",
                details={"cvss": 8.0, "confidence_score": 0.9, "confidence": "confirmed"},
            ),
        ],
        metadata={"generated_at": "2024-01-01T00:00:00Z"},
    )

    pdf_bytes = render_pdf(result)

    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0


def test_get_severity_color() -> None:
    """Test _get_severity_color function."""
    assert _get_severity_color("Critical") == "#dc3545"
    assert _get_severity_color("High") == "#fd7e14"
    assert _get_severity_color("Medium") == "#ffc107"
    assert _get_severity_color("Low") == "#17a2b8"
    assert _get_severity_color("Info") == "#6c757d"
    assert _get_severity_color("Unknown") == "#6c757d"


def test_render_pdf_with_xml_and_html_evidence() -> None:
    """Test PDF rendering survives unclosed XML/HTML in evidence and summaries."""
    result = ScanResult(
        target="http://example.com/search?q=<script>alert(1)</script>",
        findings=[
            Finding(
                kind="sqli-error",
                target="http://example.com/search?q=1' <unclosed>",
                parameter="q",
                details={
                    "summary": "SQL syntax error with <script> and & entities",
                    "cvss": 8.5,
                    "confidence": "high",
                    "evidence_pairs": [
                        {
                            "request": {
                                "method": "GET",
                                "url": "http://example.com/search?q=1' <foo>",
                            },
                            "response": {
                                "status": 500,
                                "content_type": "text/html",
                                "body": "<html><body><div>Syntax error near '<unclosed> & 1 < 2'</body></html>",
                            },
                        }
                    ],
                },
            )
        ],
        metadata={
            "generated_at": "2024-01-01T00:00:00Z",
            "timeline": [
                {
                    "timestamp": "2024-01-01T00:00:01Z",
                    "phase": "Detection <Phase>",
                    "message": "Found payload with <>& chars",
                }
            ],
        },
    )

    pdf_bytes = render_pdf(result)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 0
