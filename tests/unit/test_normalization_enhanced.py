"""Unit tests for enhanced normalization features."""

from __future__ import annotations

import pytest

from stealthix.core.models import Finding
from stealthix.detection.normalization import (
    _correlate_signals,
    _different_technique,
    _multi_probe_score,
    _same_parameter,
    normalize_findings,
)


def test_multi_probe_score_single_technique() -> None:
    """Test multi-probe score with single technique."""
    details = {
        "techniques": ["boolean"],
    }

    score = _multi_probe_score("sqli-boolean", details)

    assert score == 0.0  # No boost for single probe


def test_multi_probe_score_multiple_techniques() -> None:
    """Test multi-probe score with multiple techniques."""
    details = {
        "techniques": ["boolean", "time", "error"],
    }

    score = _multi_probe_score("sqli-boolean", details)

    assert score == 0.15  # High boost for 3+ techniques


def test_multi_probe_score_two_techniques() -> None:
    """Test multi-probe score with two techniques."""
    details = {
        "techniques": ["boolean", "time"],
    }

    score = _multi_probe_score("sqli-boolean", details)

    assert score == 0.10  # Moderate boost for 2 techniques


def test_multi_probe_score_no_techniques() -> None:
    """Test multi-probe score with no techniques."""
    details = {}

    score = _multi_probe_score("sqli-boolean", details)

    assert score == -0.05  # Penalty for no clear technique


def test_multi_probe_score_case_insensitive() -> None:
    """Test that technique detection is case-insensitive."""
    details = {
        "techniques": ["BOOLEAN", "TIME", "ERROR"],
    }

    score = _multi_probe_score("sqli-boolean", details)

    assert score == 0.15  # Should detect techniques regardless of case


def test_same_parameter_true() -> None:
    """Test _same_parameter returns True for same parameter."""
    f1 = Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={})
    f2 = Finding(kind="sqli-time", target="http://example.com", parameter="id", details={})

    assert _same_parameter(f1, f2) is True


def test_same_parameter_false() -> None:
    """Test _same_parameter returns False for different parameters."""
    f1 = Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={})
    f2 = Finding(kind="sqli-time", target="http://example.com", parameter="name", details={})

    assert _same_parameter(f1, f2) is False


def test_same_parameter_from_details() -> None:
    """Test _same_parameter uses details when parameter is None."""
    f1 = Finding(
        kind="sqli-boolean",
        target="http://example.com",
        parameter=None,
        details={"parameter": "id"},
    )
    f2 = Finding(kind="sqli-time", target="http://example.com", parameter="id", details={})

    assert _same_parameter(f1, f2) is True


def test_different_technique_different_injection_types() -> None:
    """Test _different_technique returns True for different injection types."""
    f1 = Finding(kind="sqli-boolean", target="http://example.com", details={})
    f2 = Finding(kind="nosqli-mongodb", target="http://example.com", details={})

    assert _different_technique(f1, f2) is True


def test_different_technique_different_suffixes() -> None:
    """Test _different_technique returns True for different technique suffixes."""
    f1 = Finding(kind="sqli-boolean", target="http://example.com", details={})
    f2 = Finding(kind="sqli-time", target="http://example.com", details={})

    assert _different_technique(f1, f2) is True


def test_different_technique_same_suffix() -> None:
    """Test _different_technique returns True for different injection types with same suffix."""
    f1 = Finding(kind="sqli-boolean", target="http://example.com", details={})
    f2 = Finding(kind="nosqli-boolean", target="http://example.com", details={})

    # Different injection types (sqli vs nosqli) are considered different techniques
    assert _different_technique(f1, f2) is True


def test_correlate_signals_same_parameter_different_technique() -> None:
    """Test signal correlation for same parameter with different techniques."""
    findings = [
        Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={}),
        Finding(kind="sqli-time", target="http://example.com", parameter="id", details={}),
    ]

    correlation_map = _correlate_signals(findings)

    # Both findings should get correlation boost
    assert len(correlation_map) == 2
    assert all(score == 0.1 for score in correlation_map.values())


def test_correlate_signals_different_parameters() -> None:
    """Test signal correlation for different parameters."""
    findings = [
        Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={}),
        Finding(kind="sqli-time", target="http://example.com", parameter="name", details={}),
    ]

    correlation_map = _correlate_signals(findings)

    # No correlation boost for different parameters
    assert len(correlation_map) == 0


def test_correlate_signals_same_technique() -> None:
    """Test signal correlation for same technique."""
    findings = [
        Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={}),
        Finding(kind="sqli-boolean", target="http://example.com", parameter="id", details={}),
    ]

    correlation_map = _correlate_signals(findings)

    # No correlation boost for same technique
    assert len(correlation_map) == 0


def test_normalize_findings_with_correlation() -> None:
    """Test that normalize_findings applies correlation boost for same parameter."""
    findings = [
        Finding(
            kind="sqli-boolean",
            target="http://example.com",
            parameter="id",
            details={"signals": ["sql-error"], "confidence_score": 0.7},
        ),
        Finding(
            kind="sqli-time",
            target="http://example.com",
            parameter="id",
            details={"signals": ["timing-outlier"], "confidence_score": 0.75},
        ),
    ]

    normalized = normalize_findings(findings)

    # Findings with different kinds are not merged, but correlation boost is applied
    assert len(normalized) == 2
    # Correlation boost should increase confidence score for both
    for finding in normalized:
        assert isinstance(finding.details, dict)
        assert finding.details.get("confidence_score", 0) > 0.75
        assert finding.details.get("correlation_boost", 0) > 0


def test_normalize_findings_correlation_boost_recorded() -> None:
    """Test that correlation boost is recorded in details."""
    findings = [
        Finding(
            kind="sqli-boolean",
            target="http://example.com",
            parameter="id",
            details={"signals": ["sql-error"], "confidence_score": 0.7},
        ),
        Finding(
            kind="sqli-time",
            target="http://example.com",
            parameter="id",
            details={"signals": ["timing-outlier"], "confidence_score": 0.75},
        ),
    ]

    normalized = normalize_findings(findings)

    assert isinstance(normalized[0].details, dict)
    assert "correlation_boost" in normalized[0].details
    assert normalized[0].details["correlation_boost"] > 0


def test_normalize_findings_no_correlation_single_finding() -> None:
    """Test that single finding gets no correlation boost."""
    findings = [
        Finding(
            kind="sqli-boolean",
            target="http://example.com",
            parameter="id",
            details={"signals": ["sql-error"], "confidence_score": 0.7},
        ),
    ]

    normalized = normalize_findings(findings)

    assert len(normalized) == 1
    assert isinstance(normalized[0].details, dict)
    assert normalized[0].details.get("correlation_boost") is None


def test_multi_probe_confidence_increased() -> None:
    """Test that multi-probe confirmation increases confidence."""
    findings = [
        Finding(
            kind="sqli-boolean",
            target="http://example.com",
            parameter="id",
            details={
                "signals": ["sql-error"],
                "techniques": ["boolean", "time", "error"],
            },
        ),
    ]

    normalized = normalize_findings(findings)

    assert isinstance(normalized[0].details, dict)
    # Multi-probe should increase confidence
    assert normalized[0].details.get("confidence_score", 0) > 0.84  # Base for boolean is 0.84


def test_single_probe_no_confidence_boost() -> None:
    """Test that single probe gets no multi-probe boost but may get signal boost."""
    findings = [
        Finding(
            kind="sqli-boolean",
            target="http://example.com",
            parameter="id",
            details={
                "signals": [],
                "techniques": ["boolean"],
            },
        ),
    ]

    normalized = normalize_findings(findings)

    assert isinstance(normalized[0].details, dict)
    # Single probe should get no multi-probe boost (0.0)
    # Base confidence for boolean is 0.84, no signals means no signal boost
    assert normalized[0].details.get("confidence_score", 0) == 0.84
