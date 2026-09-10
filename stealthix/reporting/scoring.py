from __future__ import annotations

from typing import Any

from stealthix.core.models import Finding, ScanResult


def _round_up_1_decimal(value: float) -> float:
    return (int(value * 10 + 0.999999) / 10.0) if value > 0 else 0.0


def _weights() -> dict[str, dict[str, float]]:
    return {
        "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
        "AC": {"L": 0.77, "H": 0.44},
        "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
        "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
        "UI": {"N": 0.85, "R": 0.62},
        "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
        "E": {"X": 1.0, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.0},
        "RL": {"X": 1.0, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.0},
        "RC": {"X": 1.0, "U": 0.92, "R": 0.96, "C": 1.0},
        "REQ": {"X": 1.0, "L": 0.5, "M": 1.0, "H": 1.5},
    }


def _metric(metrics: dict[str, str], key: str, default: str) -> str:
    return str(metrics.get(key, default) or default).upper()


def _base_score(metrics: dict[str, str]) -> float:
    w = _weights()
    av = w["AV"][_metric(metrics, "AV", "N")]
    ac = w["AC"][_metric(metrics, "AC", "L")]
    scope = _metric(metrics, "S", "U")
    pr_key = "PR_C" if scope == "C" else "PR_U"
    pr = w[pr_key][_metric(metrics, "PR", "N")]
    ui = w["UI"][_metric(metrics, "UI", "N")]
    c = w["CIA"][_metric(metrics, "C", "H")]
    i = w["CIA"][_metric(metrics, "I", "H")]
    a = w["CIA"][_metric(metrics, "A", "H")]
    exploitability = 8.22 * av * ac * pr * ui
    impact_sub = 1 - (1 - c) * (1 - i) * (1 - a)
    if scope == "C":
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
        base = 1.08 * (impact + exploitability)
    else:
        impact = 6.42 * impact_sub
        base = impact + exploitability
    if impact <= 0:
        return 0.0
    return min(10.0, _round_up_1_decimal(base))


def _temporal_multiplier(metrics: dict[str, str] | None) -> float:
    if not isinstance(metrics, dict) or not metrics:
        return 1.0
    w = _weights()
    exploit_code_maturity = w["E"][_metric(metrics, "E", "X")]
    remediation_level = w["RL"][_metric(metrics, "RL", "X")]
    report_confidence = w["RC"][_metric(metrics, "RC", "X")]
    return exploit_code_maturity * remediation_level * report_confidence


def _temporal_score(base_score: float, metrics: dict[str, str] | None) -> float:
    return (
        _round_up_1_decimal(base_score * _temporal_multiplier(metrics)) if base_score > 0 else 0.0
    )


def _merge_modified_metrics(base_metrics: dict[str, str], env: dict[str, str]) -> dict[str, str]:
    merged = dict(base_metrics)
    replacements = {
        "AV": "MAV",
        "AC": "MAC",
        "PR": "MPR",
        "UI": "MUI",
        "S": "MS",
        "C": "MC",
        "I": "MI",
        "A": "MA",
    }
    for base_key, modified_key in replacements.items():
        modified_value = env.get(modified_key)
        if modified_value not in (None, "", "X"):
            merged[base_key] = str(modified_value)
    return merged


def _environmental_score(
    base_metrics: dict[str, str],
    temporal_metrics: dict[str, str] | None,
    environmental_metrics: dict[str, str] | None,
) -> float:
    if not isinstance(environmental_metrics, dict) or not environmental_metrics:
        return _temporal_score(_base_score(base_metrics), temporal_metrics)
    w = _weights()
    modified = _merge_modified_metrics(base_metrics, environmental_metrics)
    scope = _metric(modified, "S", _metric(base_metrics, "S", "U"))
    av = w["AV"][_metric(modified, "AV", "N")]
    ac = w["AC"][_metric(modified, "AC", "L")]
    pr_key = "PR_C" if scope == "C" else "PR_U"
    pr = w[pr_key][_metric(modified, "PR", "N")]
    ui = w["UI"][_metric(modified, "UI", "N")]
    cr = w["REQ"][_metric(environmental_metrics, "CR", "X")]
    ir = w["REQ"][_metric(environmental_metrics, "IR", "X")]
    ar = w["REQ"][_metric(environmental_metrics, "AR", "X")]
    c = min(1.0, w["CIA"][_metric(modified, "C", "H")] * cr)
    i = min(1.0, w["CIA"][_metric(modified, "I", "H")] * ir)
    a = min(1.0, w["CIA"][_metric(modified, "A", "H")] * ar)
    exploitability = 8.22 * av * ac * pr * ui
    impact_sub = min(0.915, 1 - (1 - c) * (1 - i) * (1 - a))
    if scope == "C":
        impact = 7.52 * (impact_sub - 0.029) - 3.25 * (impact_sub - 0.02) ** 15
        score = 1.08 * (impact + exploitability)
    else:
        impact = 6.42 * impact_sub
        score = impact + exploitability
    if impact <= 0:
        return 0.0
    return min(10.0, _round_up_1_decimal(score * _temporal_multiplier(temporal_metrics)))


def severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0:
        return "Low"
    return "Info"


def score_cvss_breakdown(
    metrics: dict[str, str],
    temporal_metrics: dict[str, str] | None = None,
    environmental_metrics: dict[str, str] | None = None,
) -> dict[str, Any]:
    if not isinstance(metrics, dict):
        metrics = {}
    nested_temporal = metrics.get("temporal") if isinstance(metrics.get("temporal"), dict) else None
    nested_environmental = (
        metrics.get("environmental") if isinstance(metrics.get("environmental"), dict) else None
    )
    base_metrics = {
        key: str(value)
        for key, value in metrics.items()
        if key not in {"temporal", "environmental"}
    }
    temporal: dict[str, str] | None = (
        temporal_metrics
        if isinstance(temporal_metrics, dict)
        else nested_temporal
        if isinstance(nested_temporal, dict)
        else None
    )
    environmental: dict[str, str] | None = (
        environmental_metrics
        if isinstance(environmental_metrics, dict)
        else nested_environmental
        if isinstance(nested_environmental, dict)
        else None
    )
    base = _base_score(base_metrics)
    temporal_score = _temporal_score(base, temporal)
    environmental_score = _environmental_score(base_metrics, temporal, environmental)
    final_score = environmental_score if environmental else temporal_score if temporal else base
    return {
        "base": base,
        "temporal": temporal_score,
        "environmental": environmental_score,
        "score": final_score,
        "severity": severity_from_score(final_score),
        "base_metrics": base_metrics,
        "temporal_metrics": temporal,
        "environmental_metrics": environmental,
    }


def score_cvss(
    metrics: dict[str, str],
    temporal_metrics: dict[str, str] | None = None,
    environmental_metrics: dict[str, str] | None = None,
) -> float:
    return float(
        score_cvss_breakdown(
            metrics, temporal_metrics=temporal_metrics, environmental_metrics=environmental_metrics
        )["score"]
    )


def _default_metrics(kind: str) -> dict[str, str]:
    mapping = {
        "sqli": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "sqli-boolean": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "sqli-time": {
            "AV": "N",
            "AC": "H",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "L",
            "I": "L",
            "A": "L",
        },
        "sqli-error": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "L",
            "I": "L",
            "A": "N",
        },
        "sqli-union": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "sqli-stacked": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "nosqli-mongo": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "nosqli-couchdb": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "newsql": {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "C",
            "C": "H",
            "I": "H",
            "A": "H",
        },
        "idor": {
            "AV": "N",
            "AC": "L",
            "PR": "L",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "L",
            "A": "N",
        },
    }
    return mapping.get(
        kind, {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "L"}
    )


def score_finding(finding: Finding) -> float:
    metrics = finding.details.get("cvss_metrics") if isinstance(finding.details, dict) else None
    if not metrics:
        metrics = _default_metrics(finding.kind)
    return score_cvss(metrics)


def score_finding_breakdown(finding: Finding) -> dict[str, Any]:
    details = finding.details if isinstance(finding.details, dict) else {}
    metrics = (
        details.get("cvss_metrics")
        if isinstance(details.get("cvss_metrics"), dict)
        else _default_metrics(finding.kind)
    )
    temporal_metrics = (
        details.get("cvss_temporal_metrics")
        if isinstance(details.get("cvss_temporal_metrics"), dict)
        else None
    )
    environmental_metrics = (
        details.get("cvss_environmental_metrics")
        if isinstance(details.get("cvss_environmental_metrics"), dict)
        else None
    )
    if not metrics:
        return score_cvss_breakdown(_default_metrics(finding.kind))
    return score_cvss_breakdown(
        metrics, temporal_metrics=temporal_metrics, environmental_metrics=environmental_metrics
    )


def score_result(result: ScanResult) -> dict[str, Any]:
    breakdowns = [score_finding_breakdown(f) for f in result.findings]
    scores = [float(item["score"]) for item in breakdowns]
    base_scores = [float(item["base"]) for item in breakdowns]
    temporal_scores = [float(item["temporal"]) for item in breakdowns]
    environmental_scores = [float(item["environmental"]) for item in breakdowns]
    highest = max(scores) if scores else 0.0
    average = sum(scores) / len(scores) if scores else 0.0
    severity_counts = dict.fromkeys(["Critical", "High", "Medium", "Low", "Info"], 0)
    for item in breakdowns:
        severity_counts[str(item["severity"])] += 1
    risk_index = min(
        100,
        int(
            round(
                highest * 8
                + severity_counts["Critical"] * 15
                + severity_counts["High"] * 10
                + severity_counts["Medium"] * 5
                + severity_counts["Low"] * 2
            )
        ),
    )
    return {
        "highest": highest,
        "average": round(average, 1),
        "base_highest": max(base_scores) if base_scores else 0.0,
        "temporal_highest": max(temporal_scores) if temporal_scores else 0.0,
        "environmental_highest": max(environmental_scores) if environmental_scores else 0.0,
        "scores": scores,
        "breakdowns": breakdowns,
        "severity_counts": severity_counts,
        "risk_index": risk_index,
    }


__all__ = [
    "score_cvss",
    "score_cvss_breakdown",
    "score_finding",
    "score_finding_breakdown",
    "score_result",
    "severity_from_score",
]
