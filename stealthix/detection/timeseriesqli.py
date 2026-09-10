from __future__ import annotations

from typing import Any

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
from stealthix.utils import load_rust_core, resolve_payloads


def _encode_payload(payload: str) -> str:
    rust = load_rust_core()
    encoder_cls = rust.get("PayloadEncoder")
    if encoder_cls:
        encoder = encoder_cls()
        return encoder.double_url_encode(payload)
    from urllib.parse import quote

    return quote(quote(payload, safe=""), safe="")


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, str] | None = None,
    method: str | None = None,
) -> tuple[str, float]:
    return make_request(session, url, data, method)


_SUPPORTED_BACKENDS = ("influxdb", "prometheus")


def _custom_payloads(session: ScanSession, key: str) -> list[str] | None:
    custom = session.config.custom_payloads
    if not isinstance(custom, dict):
        return None
    payloads = custom.get(key)
    if isinstance(payloads, list):
        return [str(item) for item in payloads if str(item or "").strip()]
    return None


def load_payloads(kind: str, **kwargs: Any) -> list[str]:
    return resolve_payloads(kind, **kwargs)


def _payloads_for_backend(session: ScanSession, backend: str) -> list[str]:
    custom = _custom_payloads(session, "timeseriesqli")
    if backend == "influxdb":
        payloads = [
            'from() |> filter(fn: (r.field == "1"))',
            'SELECT * WHERE field = "1"',
            'from() |> filter(fn: (r.field eq "1"))',
            "SELECT * WHERE field = 1",
        ]
    elif backend == "prometheus":
        payloads = [
            'metric_name{label="1"}',
            'metric_name{label="value"}',
            "metric_name{label=1}",
            "metric_name",
        ]
    else:
        payloads = []

    if custom:
        payloads.extend(custom)

    return payloads


def _active_backends(session: ScanSession) -> tuple[str, ...]:
    dbms = str(session.config.dbms or "").strip().lower()
    return (dbms,) if dbms in _SUPPORTED_BACKENDS else _SUPPORTED_BACKENDS


def _pick_points(points: list[InjectionPoint], names: set[str]) -> list[InjectionPoint]:
    preferred = [p for p in points if p.name.lower() in names]
    return preferred or points


def _backend_signals(backend: str, body: str, payload: str) -> list[str]:
    lower = body.lower()
    if backend == "influxdb":
        return [
            signal
            for signal, present in {
                "influxdb-keyword": "influxdb" in lower,
                "flux-keyword": "flux" in lower,
                "influxql-keyword": "influxql" in lower,
                "influxdb-error": "error" in lower
                and ("influxdb" in lower or "flux" in lower or "influxql" in lower),
            }.items()
            if present
        ]
    if backend == "prometheus":
        return [
            signal
            for signal, present in {
                "prometheus-keyword": "prometheus" in lower,
                "promql-keyword": "promql" in lower,
                "prometheus-error": "parse error" in lower
                and ("prometheus" in lower or "promql" in lower),
            }.items()
            if present
        ]
    return []


def detect_timeseriesqli(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
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
        points = [
            InjectionPoint(name="query", location=loc),
            InjectionPoint(name="q", location=loc),
            InjectionPoint(name="filter", location=loc),
        ]
    findings: list[Finding] = []
    point_preferences = {
        "influxdb": {"query", "q", "filter"},
        "prometheus": {"query", "q", "filter"},
    }
    for backend in _active_backends(session):
        payloads = _payloads_for_backend(session, backend)
        for point in _pick_points(points, point_preferences.get(backend, set())):
            record_tested_param(session, module=f"timeseriesqli-{backend}", point=point)
            for payload in payloads:
                encoded = _encode_payload(payload)
                if method_uses_body(session.config.method):
                    target, data = apply_payload(session, point, payload)
                    body, elapsed = _make_request(session, target, data, "POST")
                else:
                    target, _ = apply_payload(session, point, encoded)
                    body, elapsed = _make_request(session, target)
                signals = _backend_signals(backend, body, payload)
                if signals:
                    findings.append(
                        Finding(
                            kind=f"timeseriesqli-{backend}",
                            target=target,
                            details={
                                "parameter": point.name,
                                "location": point.location,
                                "backend": backend,
                                "payload": payload,
                                "elapsed": elapsed,
                                "signals": signals,
                            },
                            parameter=point.name,
                            location=point.location,
                        )
                    )
    return findings


__all__ = ["detect_timeseriesqli"]
