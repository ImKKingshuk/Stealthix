from __future__ import annotations

from typing import Any
from urllib.parse import quote

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
from stealthix.payloads.nosql_advanced import get_advanced_payloads
from stealthix.utils import load_rust_core, resolve_payloads


def _encode_payload(payload: str) -> str:
    rust = load_rust_core()
    encoder_cls = rust.get("PayloadEncoder")
    if encoder_cls:
        encoder = encoder_cls()
        return encoder.double_url_encode(payload)
    return quote(quote(payload, safe=""), safe="")


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, str] | None = None,
    method: str | None = None,
) -> tuple[str, float]:
    return make_request(session, url, data, method)


_SUPPORTED_BACKENDS = ("mongodb", "couchdb", "redis", "cassandra", "firebase", "dynamodb")


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
    custom = _custom_payloads(session, "nosqli")
    if backend == "mongodb":
        try:
            return load_payloads(
                "nosqli",
                custom_payloads=custom,
                expand=True,
                risk=session.config.risk,
                include_advanced=True,
                advanced_backend="mongodb",
            )
        except TypeError:
            return load_payloads("nosqli")
    seeds = custom if custom is not None else get_advanced_payloads(backend)
    try:
        return load_payloads(
            "nosqli",
            custom_payloads=seeds,
            expand=True,
            risk=session.config.risk,
            include_advanced=False,
        )
    except TypeError:
        return load_payloads("nosqli")


def _active_backends(session: ScanSession) -> tuple[str, ...]:
    dbms = str(session.config.dbms or "").strip().lower()
    return (dbms,) if dbms in _SUPPORTED_BACKENDS else _SUPPORTED_BACKENDS


def _pick_points(points: list[InjectionPoint], names: set[str]) -> list[InjectionPoint]:
    preferred = [p for p in points if p.name.lower() in names]
    return preferred or points


def _backend_signals(backend: str, body: str, payload: str) -> list[str]:
    lower = body.lower()
    payload_lower = payload.lower()
    if backend == "mongodb":
        return [
            signal
            for signal, present in {
                "mongo-operator-where": "$where" in payload_lower
                and ("javascript" in lower or "where" in lower),
                "mongo-operator-regex": "$regex" in payload_lower
                and ("regex" in lower or "pattern" in lower),
                "mongo-keyword": "mongo" in lower,
                "bson-keyword": "bson" in lower,
                "json-schema-keyword": "$jsonschema" in payload_lower
                and ("schema" in lower or "validator" in lower),
            }.items()
            if present
        ]
    if backend == "couchdb":
        return [
            signal
            for signal, present in {
                "couch-keyword": "couch" in lower,
                "couch-no-db-file": "no_db_file" in lower,
                "couch-missing-view": "missing_named_view" in lower,
                "couch-not-found": '"error":"not_found"' in lower.replace(" ", ""),
            }.items()
            if present
        ]
    if backend == "redis":
        return [
            signal
            for signal, present in {
                "redis-version": "redis_version" in lower,
                "redis-pong": "pong" in lower,
                "redis-unknown-command": "unknown command" in lower,
                "redis-module-list": "module list" in payload_lower and "module" in lower,
            }.items()
            if present
        ]
    if backend == "cassandra":
        return [
            signal
            for signal, present in {
                "cassandra-keyword": "cassandra" in lower,
                "datastax-keyword": "com.datastax" in lower,
                "cql-keyword": "cql" in lower,
                "cassandra-syntax-error": "syntax error" in lower,
            }.items()
            if present
        ]
    if backend == "firebase":
        return [
            signal
            for signal, present in {
                "firebase-keyword": "firebase" in lower,
                "firebase-permission-denied": "permission_denied" in lower,
                "firebase-index-hint": ".indexon" in lower,
            }.items()
            if present
        ]
    if backend == "dynamodb":
        return [
            signal
            for signal, present in {
                "dynamodb-keyword": "dynamodb" in lower,
                "dynamodb-validation": "validationexception" in lower,
                "dynamodb-conditional-check": "conditionalcheckfailedexception" in lower,
            }.items()
            if present
        ]
    return []


def detect_nosqli(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
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
            InjectionPoint(name="filter", location=loc),
            InjectionPoint(name="query", location=loc),
            InjectionPoint(name="cmd", location=loc),
        ]
    findings: list[Finding] = []
    point_preferences = {
        "mongodb": {"filter", "query"},
        "couchdb": {"query", "filter"},
        "redis": {"cmd", "command", "query", "filter"},
        "cassandra": {"query", "filter"},
        "firebase": {"query", "filter", "orderBy"},
        "dynamodb": {"query", "filter"},
    }
    for backend in _active_backends(session):
        payloads = _payloads_for_backend(session, backend)
        for point in _pick_points(points, point_preferences.get(backend, set())):
            record_tested_param(session, module=f"nosqli-{backend}", point=point)
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
                            kind=f"nosqli-{backend}",
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
