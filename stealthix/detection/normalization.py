from __future__ import annotations

from copy import deepcopy
from typing import Any
from urllib.parse import urlparse

from stealthix.core.models import Finding


def _dedupe_list(values: list[str]) -> list[str]:
    seen: set[str] = set()
    output: list[str] = []
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _finding_key(finding: Finding) -> tuple[str, str, str, str]:
    details = finding.details if isinstance(finding.details, dict) else {}
    parameter = str(finding.parameter or details.get("parameter") or "")
    location = str(finding.location or details.get("location") or "")
    if parameter or location:
        parsed = urlparse(finding.target)
        target_key = parsed.path or finding.target
    else:
        target_key = finding.target
    return (finding.kind, parameter, location, target_key)


def _base_confidence(kind: str) -> float:
    mapping = {
        "sqli-oob": 0.98,
        "sqli-second-order": 0.96,
        "graphql-introspection": 0.95,
        "sqli-union": 0.92,
        "sqli-error": 0.9,
        "sqli-boolean": 0.84,
        "graphql-endpoint": 0.8,
        "graphql-error-probe": 0.72,
        "graphql-variables-probe": 0.65,
        "sqli-time": 0.78,
        "sqli-stacked": 0.78,
        "newsql": 0.7,
        "idor": 0.68,
        "sqli": 0.55,
    }
    if kind.startswith("nosqli-"):
        return 0.68
    return mapping.get(kind, 0.6)


def _confidence_score(kind: str, details: dict[str, Any]) -> float:
    score = _base_confidence(kind)
    signals = details.get("signals") if isinstance(details.get("signals"), list) else []
    signals = signals if isinstance(signals, list) else []
    signal_set = {str(item).strip() for item in signals if str(item).strip()}
    errors = details.get("errors") if isinstance(details.get("errors"), list) else []
    errors = errors if isinstance(errors, list) else []
    observed_payloads = (
        details.get("observed_payloads")
        if isinstance(details.get("observed_payloads"), list)
        else []
    )
    observed_payloads = observed_payloads if isinstance(observed_payloads, list) else []
    evidence_count = max(int(details.get("evidence_count", 1) or 1), 1)

    score += min(0.12, 0.04 * len(signal_set))
    score += min(0.08, 0.02 * len(errors))
    score += min(0.08, 0.02 * max(len(observed_payloads) - 1, 0))
    score += min(0.12, 0.03 * max(evidence_count - 1, 0))

    # Add multi-probe confirmation boost
    score += _multi_probe_score(kind, details)

    ratio = float(details.get("ratio", 0.0) or 0.0)
    difference = float(details.get("difference", 0.0) or 0.0)
    control_difference = float(details.get("control_difference", 0.0) or 0.0)
    elapsed = float(details.get("elapsed", 0.0) or 0.0)
    baseline = float(details.get("baseline", 0.0) or 0.0)

    if kind == "sqli-boolean":
        if ratio >= 0.2:
            score += 0.06
        if difference >= 150:
            score += 0.05
    elif kind in {"sqli-time", "sqli-stacked", "newsql"} and elapsed > baseline:
        if elapsed - baseline >= 2.0:
            score += 0.08
    elif kind == "idor":
        if difference >= 100:
            score += 0.05
        if control_difference >= 80:
            score += 0.08
        if "control-mismatch" in signal_set:
            score += 0.05
    elif kind == "sqli" and not errors and "sql-error-signature" not in signal_set:
        score -= 0.1

    return max(0.05, min(0.99, round(score, 2)))


def _confidence_label(score: float) -> str:
    if score >= 0.9:
        return "confirmed"
    if score >= 0.75:
        return "high"
    if score >= 0.55:
        return "medium"
    return "low"


def _multi_probe_score(kind: str, details: dict[str, Any]) -> float:
    """Calculate confidence boost based on multi-probe confirmation.

    Args:
        kind: Finding kind
        details: Finding details

    Returns:
        Confidence score adjustment
    """
    techniques = details.get("techniques", [])
    if not isinstance(techniques, list):
        techniques = []

    technique_set = {str(t).lower() for t in techniques}
    has_boolean = any("boolean" in t for t in technique_set)
    has_time = any("time" in t or "timing" in t for t in technique_set)
    has_error = any("error" in t for t in technique_set)
    has_union = any("union" in t for t in technique_set)
    has_stacked = any("stacked" in t for t in technique_set)

    probe_count = sum([has_boolean, has_time, has_error, has_union, has_stacked])

    # Boost confidence for multiple probe types
    if probe_count >= 3:
        return 0.15  # High confidence boost for 3+ techniques
    elif probe_count == 2:
        return 0.10  # Moderate boost for 2 techniques
    elif probe_count == 1:
        return 0.0  # No boost for single probe
    else:
        return -0.05  # Penalty for no clear technique


def _correlate_signals(findings: list[Finding]) -> dict[tuple[str, str, str, str], float]:
    """Correlate signals across findings to reduce false positives.

    Args:
        findings: List of findings to correlate

    Returns:
        Dictionary mapping finding keys to correlation scores
    """
    correlation_map: dict[tuple[str, str, str, str], float] = {}

    for i, f1 in enumerate(findings):
        for j, f2 in enumerate(findings):
            if i >= j:  # Avoid duplicate checks and self-comparison
                continue

            # Check if findings are for same parameter but different techniques
            if _same_parameter(f1, f2) and _different_technique(f1, f2):
                key1 = _finding_key(f1)
                key2 = _finding_key(f2)
                correlation_map[key1] = correlation_map.get(key1, 0.0) + 0.1
                correlation_map[key2] = correlation_map.get(key2, 0.0) + 0.1

    return correlation_map


def _same_parameter(f1: Finding, f2: Finding) -> bool:
    """Check if two findings target the same parameter.

    Args:
        f1: First finding
        f2: Second finding

    Returns:
        True if same parameter
    """
    param1 = f1.parameter or (f1.details or {}).get("parameter")
    param2 = f2.parameter or (f2.details or {}).get("parameter")
    return str(param1 or "") == str(param2 or "") and bool(param1)


def _different_technique(f1: Finding, f2: Finding) -> bool:
    """Check if two findings use different detection techniques.

    Args:
        f1: First finding
        f2: Second finding

    Returns:
        True if different techniques
    """
    kind1 = str(f1.kind or "").lower()
    kind2 = str(f2.kind or "").lower()

    # Same kind means same technique
    if kind1 == kind2:
        return False

    # Different if they have different injection types
    type1 = kind1.split("-")[0] if "-" in kind1 else kind1
    type2 = kind2.split("-")[0] if "-" in kind2 else kind2

    if type1 != type2:
        return True

    # Different if they have different techniques (boolean, time, error, union)
    techniques1 = set()
    techniques2 = set()

    for suffix in ["boolean", "time", "error", "union", "stacked"]:
        if suffix in kind1:
            techniques1.add(suffix)
        if suffix in kind2:
            techniques2.add(suffix)

    return techniques1 != techniques2


def _prepare_details(finding: Finding) -> dict[str, Any]:
    details = deepcopy(finding.details) if isinstance(finding.details, dict) else {}
    observed_payloads = []
    if isinstance(details.get("observed_payloads"), list):
        observed_payloads.extend(
            str(item) for item in details["observed_payloads"] if str(item).strip()
        )
    payload = details.get("payload")
    if isinstance(payload, str) and payload.strip():
        observed_payloads.append(payload)
    signals = details.get("signals") if isinstance(details.get("signals"), list) else []
    signals = signals if isinstance(signals, list) else []
    details["observed_payloads"] = _dedupe_list(observed_payloads)
    details["signals"] = _dedupe_list([str(item) for item in signals])
    details["evidence_count"] = max(int(details.get("evidence_count", 1) or 1), 1)
    score = _confidence_score(finding.kind, details)
    details["confidence_score"] = score
    details["confidence"] = _confidence_label(score)
    return details


def normalize_findings(findings: list[Finding]) -> list[Finding]:
    # Calculate signal correlation before merging
    correlation_map: dict[tuple[str, str, str, str], float] = _correlate_signals(findings)

    merged: dict[tuple[str, str, str, str], Finding] = {}
    for finding in findings:
        normalized = Finding(
            kind=finding.kind,
            target=finding.target,
            details=_prepare_details(finding),
            parameter=finding.parameter,
            location=finding.location,
        )
        key = _finding_key(normalized)
        existing = merged.get(key)
        if existing is None:
            merged[key] = normalized
            continue

        existing_details = existing.details
        incoming_details = normalized.details
        for field in ("observed_payloads", "signals", "errors"):
            existing_list = (
                existing_details.get(field) if isinstance(existing_details.get(field), list) else []
            )
            incoming_list = (
                incoming_details.get(field) if isinstance(incoming_details.get(field), list) else []
            )
            existing_list = existing_list if isinstance(existing_list, list) else []
            incoming_list = incoming_list if isinstance(incoming_list, list) else []
            existing_details[field] = _dedupe_list(
                [*map(str, existing_list), *map(str, incoming_list)]
            )
        for field in ("elapsed", "difference", "ratio", "control_difference", "baseline"):
            if field in incoming_details:
                existing_details[field] = max(
                    float(existing_details.get(field, 0.0) or 0.0),
                    float(incoming_details.get(field, 0.0) or 0.0),
                )
        existing_details["evidence_count"] = int(
            existing_details.get("evidence_count", 1) or 1
        ) + int(incoming_details.get("evidence_count", 1) or 1)
        if "payload" not in existing_details and "payload" in incoming_details:
            existing_details["payload"] = incoming_details["payload"]
        score = _confidence_score(existing.kind, existing_details)
        existing_details["confidence_score"] = score
        existing_details["confidence"] = _confidence_label(score)

    # Apply correlation boost to merged findings
    for key, finding in merged.items():
        if isinstance(finding.details, dict):
            correlation_boost = (
                correlation_map.get(key, 0.0) if isinstance(correlation_map, dict) else 0.0
            )
            if correlation_boost > 0:
                current_score = float(finding.details.get("confidence_score", 0.0) or 0.0)
                finding.details["confidence_score"] = min(
                    0.99, round(current_score + correlation_boost, 2)
                )
                finding.details["confidence"] = _confidence_label(
                    finding.details["confidence_score"]
                )
                finding.details["correlation_boost"] = correlation_boost

    return sorted(
        merged.values(),
        key=lambda item: (
            -(
                float(item.details.get("confidence_score", 0.0) or 0.0)
                if isinstance(item.details, dict)
                else 0.0
            ),
            item.kind,
            item.parameter or "",
            item.target,
        ),
    )


__all__ = ["normalize_findings"]
