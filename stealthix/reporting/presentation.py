from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlparse

from stealthix.core.evidence import FindingEvidenceBundle
from stealthix.core.models import Finding, ScanResult
from stealthix.reporting.compliance import compliance_for_finding, summarize_compliance
from stealthix.reporting.scoring import score_finding_breakdown, score_result


def _list_values(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    seen: set[str] = set()
    output: list[str] = []
    for item in value:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            output.append(text)
    return output


def _truncate(value: Any, *, limit: int = 240) -> str:
    text = str(value or "").strip()
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _history_matches_finding(entry: dict[str, Any], finding: Finding) -> bool:
    url = str(entry.get("url") or "")
    if not url:
        return False
    if url == finding.target:
        return True
    if urlparse(url).path and urlparse(url).path == urlparse(finding.target).path:
        return True
    parameter = finding.parameter or str((finding.details or {}).get("parameter") or "").strip()
    if parameter and parameter.lower() in url.lower():
        return True
    return False


def _evidence_pairs(finding: Finding, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    details = finding.details if isinstance(finding.details, dict) else {}
    bundle_data = (
        details.get("evidence_bundle") if isinstance(details.get("evidence_bundle"), dict) else None
    )
    if bundle_data:
        pairs = FindingEvidenceBundle.from_dict(bundle_data).to_evidence_pairs()
        if pairs:
            return pairs[:3]
    explicit_pairs = (
        details.get("evidence_pairs") if isinstance(details.get("evidence_pairs"), list) else []
    )
    evidence: list[dict[str, Any]] = (
        [item for item in explicit_pairs if isinstance(item, dict)]
        if isinstance(explicit_pairs, list)
        else []
    )
    history = (
        metadata.get("request_history") if isinstance(metadata.get("request_history"), list) else []
    )
    if isinstance(history, list):
        for entry in history:
            if not isinstance(entry, dict) or not _history_matches_finding(entry, finding):
                continue
            meta = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
            evidence.append(
                {
                    "request": {
                        "method": entry.get("method"),
                        "url": entry.get("url"),
                        "headers": meta.get("request_headers")
                        if isinstance(meta.get("request_headers"), dict)
                        else {},
                        "body": _truncate(meta.get("request_body")),
                    },
                    "response": {
                        "status": entry.get("status") or meta.get("status_code"),
                        "content_type": meta.get("content_type"),
                        "headers": meta.get("headers")
                        if isinstance(meta.get("headers"), dict)
                        else {},
                        "body": _truncate(
                            meta.get("response_excerpt") or details.get("response_excerpt") or ""
                        ),
                        "waf_hints": meta.get("waf_hints")
                        if isinstance(meta.get("waf_hints"), list)
                        else [],
                    },
                    "timestamp": entry.get("timestamp"),
                }
            )
            if len(evidence) >= 3:
                break
    if not evidence:
        evidence.append(
            {
                "request": {
                    "method": details.get("method") or "GET",
                    "url": finding.target,
                    "headers": {},
                    "body": _truncate(
                        (details.get("observed_payloads") or [details.get("payload") or ""])[0]
                    ),
                },
                "response": {
                    "status": details.get("status_code"),
                    "content_type": details.get("content_type"),
                    "headers": {},
                    "body": _truncate((details.get("errors") or details.get("signals") or [""])[0]),
                    "waf_hints": [],
                },
                "timestamp": metadata.get("generated_at"),
            }
        )
    return evidence[:3]


def _timeline(result: ScanResult) -> list[dict[str, Any]]:
    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    events: list[dict[str, Any]] = []
    auth = metadata.get("auth") if isinstance(metadata.get("auth"), dict) else None
    if auth and auth.get("authenticated_at"):
        events.append(
            {
                "timestamp": auth.get("authenticated_at"),
                "phase": "Authentication",
                "message": f"Authenticated session established via {auth.get('auth_type', 'auth')}",
            }
        )
    crawl = metadata.get("crawl") if isinstance(metadata.get("crawl"), dict) else None
    if crawl:
        events.append(
            {
                "timestamp": metadata.get("generated_at"),
                "phase": "Crawl",
                "message": f"Discovered {crawl.get('target_count', 0)} target(s) across {crawl.get('page_count', 0)} page(s).",
            }
        )
    history = (
        metadata.get("request_history") if isinstance(metadata.get("request_history"), list) else []
    )
    if history:
        first = history[0]
        last = history[-1]
        events.append(
            {
                "timestamp": first.get("timestamp"),
                "phase": "HTTP",
                "message": f"First request: {first.get('method')} {first.get('url')}",
            }
        )
        events.append(
            {
                "timestamp": last.get("timestamp"),
                "phase": "HTTP",
                "message": f"Last request: {last.get('method')} {last.get('url')} ({last.get('status')})",
            }
        )
    if metadata.get("multi_target"):
        targets = (
            metadata.get("scanned_targets")
            if isinstance(metadata.get("scanned_targets"), list)
            else []
        )
        if targets:
            events.append(
                {
                    "timestamp": metadata.get("generated_at"),
                    "phase": "Multi-target",
                    "message": f"Scanned {len(targets)} target(s).",
                }
            )
    hostile = (
        metadata.get("hostile_target") if isinstance(metadata.get("hostile_target"), dict) else None
    )
    if hostile and hostile.get("blocked_responses"):
        events.append(
            {
                "timestamp": metadata.get("generated_at"),
                "phase": "WAF / Rate Limit",
                "message": f"Observed {hostile.get('blocked_responses')} blocked response(s) and {hostile.get('retry_count', 0)} retry event(s).",
            }
        )
    if metadata.get("generated_at"):
        events.append(
            {
                "timestamp": metadata.get("generated_at"),
                "phase": "Reporting",
                "message": "Report materialized from scan result metadata.",
            }
        )

    def sort_key(item: dict[str, Any]) -> tuple[int, str]:
        raw = item.get("timestamp")
        if isinstance(raw, (int, float)):
            return (0, str(raw))
        if isinstance(raw, str) and raw:
            try:
                parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                return (0, parsed.astimezone(UTC).isoformat())
            except ValueError:
                return (1, raw)
        return (2, "")

    return sorted(events, key=sort_key)


def summarize_finding(finding: Finding, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    details = finding.details if isinstance(finding.details, dict) else {}
    report_metadata = metadata if isinstance(metadata, dict) else {}
    parameter = finding.parameter or str(details.get("parameter") or "").strip() or None
    location = finding.location or str(details.get("location") or "").strip() or None
    confidence = str(details.get("confidence") or "unscored")
    confidence_score = float(details.get("confidence_score", 0.0) or 0.0)
    evidence_count = max(int(details.get("evidence_count", 1) or 1), 1)
    evidence_bundle = (
        FindingEvidenceBundle.from_dict(details.get("evidence_bundle")).to_dict()
        if isinstance(details.get("evidence_bundle"), dict)
        else None
    )
    signals = _list_values(details.get("signals"))
    payloads = _list_values(details.get("observed_payloads"))
    errors = _list_values(details.get("errors"))
    scoring = score_finding_breakdown(finding)
    compliance = compliance_for_finding(finding)
    evidence = _evidence_pairs(finding, report_metadata)
    if not payloads and isinstance(details.get("payload"), str):
        payload = str(details.get("payload") or "").strip()
        if payload:
            payloads = [payload]

    summary_bits = [
        f"{scoring['severity']} CVSS {scoring['score']:.1f}",
        f"confidence {confidence}",
    ]
    if confidence_score > 0:
        summary_bits[-1] = f"confidence {confidence} ({confidence_score:.2f})"
    summary_bits.append(f"evidence {evidence_count}")
    if parameter and location:
        summary_bits.insert(0, f"{parameter} [{location}]")
    elif parameter:
        summary_bits.insert(0, parameter)

    return {
        "kind": finding.kind,
        "target": finding.target,
        "parameter": parameter,
        "location": location,
        "cvss": scoring["score"],
        "cvss_base": scoring["base"],
        "cvss_temporal": scoring["temporal"],
        "cvss_environmental": scoring["environmental"],
        "severity": scoring["severity"],
        "confidence": confidence,
        "confidence_score": confidence_score,
        "evidence_count": evidence_count,
        "signals": signals,
        "observed_payloads": payloads,
        "errors": errors,
        "compliance": compliance,
        "remediation": compliance["remediation"],
        "evidence_pairs": evidence,
        "evidence_bundle": evidence_bundle,
        "summary": " | ".join(summary_bits),
        "details": details,
    }


def build_report_context(result: ScanResult) -> dict[str, Any]:
    scores = score_result(result)
    metadata = result.metadata if isinstance(result.metadata, dict) else {}
    finding_views = [summarize_finding(finding, metadata) for finding in result.findings]
    compliance_summary = summarize_compliance(result.findings)
    timeline = _timeline(result)
    top_findings = sorted(finding_views, key=lambda item: float(item["cvss"]), reverse=True)[:5]
    executive_summary = {
        "risk_score": scores["risk_index"],
        "risk_rating": "Critical"
        if scores["risk_index"] >= 85
        else "High"
        if scores["risk_index"] >= 60
        else "Medium"
        if scores["risk_index"] >= 30
        else "Low",
        "total_findings": len(finding_views),
        "highest_severity": next(
            (
                label
                for label in ["Critical", "High", "Medium", "Low", "Info"]
                if scores["severity_counts"].get(label)
            ),
            "Info",
        ),
        "highest_cvss": round(float(scores["highest"]), 1),
        "average_cvss": round(float(scores["average"]), 1),
        "top_findings": [
            {
                "kind": item["kind"],
                "target": item["target"],
                "severity": item["severity"],
                "cvss": item["cvss"],
            }
            for item in top_findings
        ],
    }
    attack_surface = {
        "request_count": len(metadata.get("request_history") or []),
        "target_count": len(metadata.get("scanned_targets") or [])
        or int((metadata.get("crawl") or {}).get("target_count", 0) or 0),
        "auth_enabled": bool(
            (metadata.get("auth") or {}).get("authenticated")
            or metadata.get("auth")
            or metadata.get("site_scan")
            or metadata.get("multi_target")
        ),
    }

    # Add reconnaissance section if available
    context = {
        "target": result.target,
        "generated_at": metadata.get("generated_at"),
        "metadata": metadata,
        "scores": scores,
        "findings": finding_views,
        "compliance": compliance_summary,
        "timeline": timeline,
        "executive_summary": executive_summary,
        "attack_surface": attack_surface,
    }

    recon_data = metadata.get("recon")
    if recon_data:
        context["reconnaissance"] = _build_recon_section(recon_data)

    return context


def _build_recon_section(recon_data: dict[str, Any]) -> dict[str, Any]:
    """Build reconnaissance section for reports."""
    return {
        "technologies": [
            {
                "category": tech.get("category"),
                "name": tech.get("name"),
                "version": tech.get("version"),
                "confidence": f"{tech.get('confidence', 0) * 100:.1f}%",
                "evidence_count": len(tech.get("evidence", [])),
            }
            for tech in recon_data.get("technologies", [])
        ],
        "endpoints": [
            {
                "url": ep.get("url"),
                "status": ep.get("status_code"),
                "size": ep.get("response_size"),
                "category": ep.get("category"),
                "confidence": f"{ep.get('confidence', 0) * 100:.1f}%",
            }
            for ep in recon_data.get("endpoints", [])
        ],
        "summary": {
            "tech_count": len(recon_data.get("technologies", [])),
            "endpoint_count": len(recon_data.get("endpoints", [])),
            "elapsed": recon_data.get("elapsed", 0),
        },
    }


__all__ = ["build_report_context", "summarize_finding"]
