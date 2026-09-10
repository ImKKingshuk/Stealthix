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


_SUPPORTED_BACKENDS = ("elasticsearch", "solr", "opensearch")


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
    custom = _custom_payloads(session, "searchqli")
    if backend == "elasticsearch":
        payloads = [
            '{"query": {"bool": {"must": [{"term": {"field": "1"}}]}}}',
            '{"query": {"match_all": {}}}',
            '{"query": {"match": {"field": "1"}}}',
            '{"query": {"term": {"field": "1"}}}',
        ]
    elif backend == "solr":
        payloads = [
            'field:value OR field:"1"',
            'field:"1" OR field:"1"',
            "field:1 OR field:1",
            "field:* OR field:*",
        ]
    elif backend == "opensearch":
        payloads = [
            '{"query": {"bool": {"must": [{"term": {"field": "1"}}]}}}',
            '{"query": {"match_all": {}}}',
            '{"query": {"match": {"field": "1"}}}',
            '{"query": {"term": {"field": "1"}}}',
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
    if backend == "elasticsearch":
        return [
            signal
            for signal, present in {
                "elasticsearch-keyword": "elasticsearch" in lower,
                "query-dsl-keyword": "query_dsl" in lower or "query" in lower and "dsl" in lower,
                "parsing-exception": "parsing_exception" in lower,
                "elasticsearch-version": "elasticsearch" in lower
                and ("version" in lower or "number" in lower),
            }.items()
            if present
        ]
    if backend == "solr":
        return [
            signal
            for signal, present in {
                "solr-keyword": "solr" in lower,
                "lucene-keyword": "lucene" in lower,
                "solr-syntax-error": "syntax error" in lower
                and ("solr" in lower or "lucene" in lower),
                "solr-version": "solr" in lower and ("version" in lower or "lucene" in lower),
            }.items()
            if present
        ]
    if backend == "opensearch":
        return [
            signal
            for signal, present in {
                "opensearch-keyword": "opensearch" in lower,
                "query-dsl-keyword": "query_dsl" in lower or "query" in lower and "dsl" in lower,
                "parsing-exception": "parsing_exception" in lower,
                "opensearch-version": "opensearch" in lower
                and ("version" in lower or "number" in lower),
            }.items()
            if present
        ]
    return []


def detect_searchqli(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
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
        "elasticsearch": {"query", "q", "filter"},
        "solr": {"query", "q", "filter"},
        "opensearch": {"query", "q", "filter"},
    }
    for backend in _active_backends(session):
        payloads = _payloads_for_backend(session, backend)
        for point in _pick_points(points, point_preferences.get(backend, set())):
            record_tested_param(session, module=f"searchqli-{backend}", point=point)
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
                            kind=f"searchqli-{backend}",
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


__all__ = ["detect_searchqli"]
