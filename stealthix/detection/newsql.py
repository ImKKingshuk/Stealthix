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
from stealthix.detection.sqli import _match_errors
from stealthix.utils import load_rust_core, resolve_payloads


def _baseline_timings(
    session: ScanSession,
    url: str,
    data: dict[str, str] | None = None,
    samples: int = 3,
) -> tuple[float, float]:
    timings: list[float] = []
    for _ in range(samples):
        if data is not None and method_uses_body(session.config.method):
            _, elapsed = _make_request(session, url, data, "POST")
        else:
            _, elapsed = _make_request(session, url)
        timings.append(elapsed)
    mean = sum(timings) / max(len(timings), 1)
    variance = sum((value - mean) ** 2 for value in timings) / max(len(timings), 1)
    return mean, variance**0.5


def _encode_payload(payload: str) -> str:
    rust = load_rust_core()
    encoder_cls = rust.get("PayloadEncoder")
    if encoder_cls:
        encoder = encoder_cls()
        return encoder.double_url_encode(payload)
    return quote(quote(payload, safe=""), safe="")


def _obfuscate(payload: str) -> str:
    rust = load_rust_core()
    obfuscator_cls = rust.get("PayloadObfuscator")
    if obfuscator_cls:
        obfuscator = obfuscator_cls()
        return obfuscator.apply(payload)
    return payload.replace(" ", "/**/").replace("SELECT", "SeLeCt")


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, str] | None = None,
    method: str | None = None,
) -> tuple[str, float]:
    return make_request(session, url, data, method)


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


def detect_newsql(session: ScanSession, param: TargetParam | None = None) -> list[Finding]:
    try:
        payloads = load_payloads(
            "newsql",
            custom_payloads=_custom_payloads(session, "newsql"),
            expand=True,
            risk=session.config.risk,
        )
    except TypeError:
        payloads = load_payloads("newsql")
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
        points = [InjectionPoint(name="query", location=loc)]
    findings: list[Finding] = []
    for point in points:
        record_tested_param(session, module="newsql", point=point)
        base_target, base_data = apply_payload(session, point, "1")
        mean, stdev = _baseline_timings(session, base_target, base_data)
        for payload in payloads:
            obfuscated = _obfuscate(payload)
            encoded = _encode_payload(obfuscated)
            if method_uses_body(session.config.method):
                target, data = apply_payload(session, point, obfuscated)
                body, elapsed = _make_request(session, target, data, "POST")
            else:
                target, _ = apply_payload(session, point, encoded)
                body, elapsed = _make_request(session, target)
            lower = body.lower()
            signals = [
                signal
                for signal, present in {
                    "cockroach-keyword": "cockroach" in lower,
                    "tidb-keyword": "tidb" in lower,
                    "spanner-keyword": "spanner" in lower,
                    "yugabyte-keyword": "yugabyte" in lower,
                    "voltdb-keyword": "volt" in lower,
                    "nuodb-keyword": "nuodb" in lower,
                    "singlestore-keyword": "singlestore" in lower or "memsql" in lower,
                    "oceanbase-keyword": "oceanbase" in lower,
                    "polardb-keyword": "polardb" in lower,
                    "tiflash-keyword": "tiflash" in lower,
                    "ycql-keyword": "ycql" in lower,
                    "newsql-error-signature": bool(_match_errors(body)),
                }.items()
                if present
            ]
            threshold = mean + max(1.0, 4 * stdev)
            if "sleep" in payload.lower() and elapsed >= threshold:
                signals.append("timing-outlier")
            if any(signal.endswith("keyword") for signal in signals) or "timing-outlier" in signals:
                findings.append(
                    Finding(
                        kind="newsql",
                        target=target,
                        details={
                            "parameter": point.name,
                            "location": point.location,
                            "payload": payload,
                            "elapsed": elapsed,
                            "baseline": mean,
                            "signals": signals,
                        },
                        parameter=point.name,
                        location=point.location,
                    )
                )
    return findings
