from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from stealthix.core.http import make_request
from stealthix.core.models import Finding, TargetParam
from stealthix.core.session import ScanSession
from stealthix.core.targeting import (
    InjectionPoint,
    apply_payload,
    discover_injection_points,
    record_tested_param,
)
from stealthix.detection.rest_api import method_uses_body


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    method: str | None = None,
) -> tuple[str, float]:
    return make_request(session, url, data, method)


def _mutate_url(url: str, key: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[key] = [value]
    new_query = urlencode(qs, doseq=True, safe=":/")
    return urlunparse(parsed._replace(query=new_query))


def _denied_markers(body: str) -> bool:
    lower = body.lower()
    return any(
        marker in lower
        for marker in (
            "not authorized",
            "unauthorized",
            "access denied",
            "forbidden",
            "permission denied",
            "not found",
            "does not exist",
            '"error":"not_found"',
        )
    )


def detect_idor(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
    findings: list[Finding] = []
    points = (
        [InjectionPoint(name=param.name, location=param.location)]
        if param
        else discover_injection_points(session)
    )
    if not points:
        loc = (
            "query"
            if not method_uses_body(session.config.method)
            else ("json" if session.config.body_format == "json" else "form")
        )
        points = [InjectionPoint(name="id", location=loc)]

    for point in points:
        record_tested_param(session, module="idor", point=point)
        baseline = "1"
        if method_uses_body(session.config.method):
            existing = (session.config.data or {}).get(point.name)
            if isinstance(existing, (int, float)) or (
                isinstance(existing, str) and existing.isdigit()
            ):
                baseline = str(existing)
        else:
            parsed = urlparse(session.config.base_url)
            qs = parse_qs(parsed.query)
            if point.name in qs and qs[point.name] and str(qs[point.name][0]).isdigit():
                baseline = str(qs[point.name][0])

        try:
            base_val = int(baseline)
        except ValueError:
            base_val = 1
        alt_val = str(base_val + 1)
        invalid_val = str(base_val + 999_999)

        if method_uses_body(session.config.method):
            target_a, data_a = apply_payload(session, point, baseline)
            target_b, data_b = apply_payload(session, point, alt_val)
            target_c, data_c = apply_payload(session, point, invalid_val)
            body_a, _ = _make_request(session, target_a, data_a, "POST")
            body_b, _ = _make_request(session, target_b, data_b, "POST")
            body_c, _ = _make_request(session, target_c, data_c, "POST")
            target = target_a
        else:
            target_a = _mutate_url(session.config.base_url, point.name, baseline)
            target_b = _mutate_url(session.config.base_url, point.name, alt_val)
            target_c = _mutate_url(session.config.base_url, point.name, invalid_val)
            body_a, _ = _make_request(session, target_a)
            body_b, _ = _make_request(session, target_b)
            body_c, _ = _make_request(session, target_c)
            target = target_a

        diff = abs(len(body_a) - len(body_b))
        control_diff = abs(len(body_b) - len(body_c))
        denied_alt = _denied_markers(body_b)
        denied_invalid = _denied_markers(body_c)
        if diff > 50 and control_diff > 40 and not denied_alt:
            signals = ["baseline-alt-difference", "control-mismatch"]
            if denied_invalid:
                signals.append("invalid-control-denied")
            findings.append(
                Finding(
                    kind="idor",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "baseline": baseline,
                        "alternate": alt_val,
                        "invalid_control": invalid_val,
                        "difference": diff,
                        "control_difference": control_diff,
                        "signals": signals,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
    return findings
