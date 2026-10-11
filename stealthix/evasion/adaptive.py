from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from stealthix.core.errors import EvasionError, NetworkError
from stealthix.core.session import ScanSession

# Import new evasion modules
from stealthix.evasion import behavioral, ml_bypass, polymorphic, protocol
from stealthix.utils.rust import load_rust_core

_SQL_KEYWORDS = {
    "ALL",
    "AND",
    "AS",
    "BY",
    "CASE",
    "FROM",
    "IF",
    "IN",
    "IS",
    "JOIN",
    "LIMIT",
    "MID",
    "NULL",
    "OR",
    "ORDER",
    "SELECT",
    "SLEEP",
    "THEN",
    "UNION",
    "WHEN",
    "WHERE",
}
_SCRIPT_ALIASES = {
    "unionalltoinon": "unionalltounion",
    "union_all": "unionalltounion",
    "charencode": "percentage",
    "utf8": "charunicodeescape",
}
_VENDOR_PROFILES = {
    "cloudflare": ["randomcomments", "chardoubleencode", "xforwardedfor"],
    "modsecurity": ["versionedmorekeywords", "space2comment", "varnish"],
    "awswaf": ["charunicodeescape", "randomcomments", "xforwardedfor"],
    "imperva": ["htmlencode", "multiplespaces", "xforwardedfor"],
    "akamai": ["charunicodeencode", "randomcomments", "xforwardedfor"],
    "f5": ["greatest", "space2comment", "xforwardedfor"],
    "generic": ["randomcomments", "space2comment", "multiplespaces"],
}
_BODY_PROFILES = {
    "json": ["charunicodeescape"],
    "xml": ["htmlencode"],
    "form": ["chardoubleencode"],
    "query": ["percentage"],
}
_BLOCKED_ESCALATION = ["versionedkeywords", "randomcomments", "chardoubleencode", "multiplespaces"]
_HEADER_MUTATORS = {"xforwardedfor", "varnish"}


@dataclass(frozen=True)
class AdaptiveCandidate:
    name: str
    url: str
    data: Any
    headers: dict[str, str] = field(default_factory=dict)
    body_format: str = "form"
    transport: str = "standard"
    pipeline: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()


def _normalize_script(name: str) -> str:
    normalized = str(name or "").strip().lower().replace("-", "_")
    return _SCRIPT_ALIASES.get(normalized, normalized)


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        normalized = _normalize_script(item)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        ordered.append(normalized)
    return ordered


def infer_waf_vendor(session: ScanSession) -> str | None:
    candidates: list[str] = []
    for source in (
        session.metadata.get("waf"),
        session.metadata.get("fingerprint"),
        session.metadata.get("hostile_target"),
    ):
        if isinstance(source, list):
            candidates.extend(str(item).lower() for item in source)
        elif isinstance(source, dict):
            hints = source.get("waf_hints") if isinstance(source.get("waf_hints"), list) else []
            candidates.extend(str(item).lower() for item in hints)
            detected = source.get("detected")
            if detected:
                candidates.append(str(detected).lower())
    for candidate in candidates:
        compact = candidate.replace(" ", "")
        for vendor in _VENDOR_PROFILES:
            if vendor != "generic" and vendor in compact:
                return vendor
    return "generic" if candidates else None


def resolve_tamper_pipeline(
    session: ScanSession, *, blocked: bool = False, body_format: str | None = None
) -> list[str]:
    explicit = list(session.config.tamper_pipeline or [])
    if explicit:
        pipeline = explicit
    else:
        vendor = infer_waf_vendor(session) or "generic"
        pipeline = list(_VENDOR_PROFILES.get(vendor, _VENDOR_PROFILES["generic"]))
    if session.config.tamper_auto:
        pipeline.extend(
            _BODY_PROFILES.get(str(body_format or session.config.body_format or "form").lower(), [])
        )
        if blocked:
            pipeline.extend(_BLOCKED_ESCALATION)
    return _dedupe(pipeline)


def _stable_ip(seed: str) -> str:
    digest = hashlib.sha256(seed.encode("utf-8")).digest()
    octets = [
        10 + (digest[0] % 200),
        1 + (digest[1] % 250),
        1 + (digest[2] % 250),
        1 + (digest[3] % 250),
    ]
    return ".".join(str(item) for item in octets)


def _mutate_headers(script: str, payload: str, headers: dict[str, str]) -> None:
    if script == "xforwardedfor":
        address = _stable_ip(payload)
        headers.setdefault("X-Forwarded-For", address)
        headers.setdefault("X-Client-IP", address)
        headers.setdefault("X-Real-IP", address)
    elif script == "varnish":
        headers.setdefault("X-originating-IP", _stable_ip("varnish:" + payload))


def _wrap_keywords(payload: str, *, prefix: str = "/*!", suffix: str = "*/") -> str:
    def repl(match: re.Match[str]) -> str:
        word = match.group(0)
        return f"{prefix}{word}{suffix}" if word.upper() in _SQL_KEYWORDS else word

    return re.sub(r"[A-Za-z_]+", repl, payload)


def _random_comments(payload: str) -> str:
    def repl(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.upper() not in _SQL_KEYWORDS or len(word) < 3:
            return word
        return word[0] + "/**/".join(word[1:-1]) + word[-1]

    return re.sub(r"[A-Za-z_]+", repl, payload)


def _multiple_spaces(payload: str) -> str:
    def repl(match: re.Match[str]) -> str:
        word = match.group(0)
        return f"  {word}   " if word.upper() in _SQL_KEYWORDS else word

    return re.sub(r"[A-Za-z_]+", repl, payload)


def _htmlencode(payload: str) -> str:
    return "".join(ch if ch.isalnum() else f"&#{ord(ch)};" for ch in payload)


def _percentage(payload: str) -> str:
    return "".join(ch if ch.isspace() else f"%{ch}" for ch in payload)


def _unicode_escape(payload: str, *, web: bool) -> str:
    return "".join(
        (f"%u{ord(ch):04X}" if web else f"\\u{ord(ch):04x}") if not ch.isspace() else ch
        for ch in payload
    )


def _double_url_encode(payload: str) -> str:
    return re.sub(r"%([0-9A-Fa-f]{2})", lambda m: f"%25{m.group(1).upper()}", payload)


def _plus_to_concat(payload: str, *, fn: bool) -> str:
    if "+" not in payload:
        return payload
    pieces = [part.strip() for part in payload.split("+")]
    if len(pieces) < 2:
        return payload
    name = "CONCAT" if not fn else "{fn CONCAT}"
    return f"{name}({','.join(pieces)})"


def _apply_python_script(script: str, payload: str) -> str:
    if script == "apostrophemask":
        return payload.replace("'", "%EF%BC%87")
    if script == "apostrophenullencode":
        return payload.replace("'", "%00%27")
    if script == "appendnullbyte":
        return payload if payload.endswith("%00") else payload + "%00"
    if script == "chardoubleencode":
        return _double_url_encode(payload)
    if script == "charunicodeencode":
        return _unicode_escape(payload, web=True)
    if script == "charunicodeescape":
        return _unicode_escape(payload, web=False)
    if script == "commalesslimit":
        return re.sub(
            r"(?i)LIMIT\s+(\d+)\s*,\s*(\d+)",
            lambda m: f"LIMIT {m.group(2)} OFFSET {m.group(1)}",
            payload,
        )
    if script == "commalessmid":
        return re.sub(
            r"(?i)MID\(([^,]+),\s*([^,]+),\s*([^\)]+)\)",
            lambda m: f"MID({m.group(1)} FROM {m.group(2)} FOR {m.group(3)})",
            payload,
        )
    if script == "commentbeforeparentheses":
        return re.sub(r"([A-Za-z_]+)\(", r"\1/**/(", payload)
    if script == "greatest":
        return re.sub(
            r"(?i)(\b)([A-Za-z0-9_]+)\s*>\s*([A-Za-z0-9_]+)",
            lambda m: f"{m.group(1)}GREATEST({m.group(2)},{m.group(3)}+1)={m.group(2)}",
            payload,
        )
    if script == "halfversionedmorekeywords":
        return _wrap_keywords(payload, prefix="/*!0", suffix="*/")
    if script == "hex2char":
        return re.sub(
            r"0x([0-9A-Fa-f]+)",
            lambda m: (
                "CONCAT("
                + ",".join(
                    f"CHAR({int(m.group(1)[i : i + 2], 16)})" for i in range(0, len(m.group(1)), 2)
                )
                + ")"
            ),
            payload,
        )
    if script == "htmlencode":
        return _htmlencode(payload)
    if script == "if2case":
        return re.sub(
            r"(?i)IF\(([^,]+),([^,]+),([^\)]+)\)",
            lambda m: (
                f"CASE WHEN ({m.group(1).strip()}) THEN ({m.group(2).strip()}) ELSE ({m.group(3).strip()}) END"
            ),
            payload,
        )
    if script == "ifnull2casewhenisnull":
        return re.sub(
            r"(?i)IFNULL\(([^,]+),([^\)]+)\)",
            lambda m: (
                f"CASE WHEN ISNULL({m.group(1).strip()}) THEN ({m.group(2).strip()}) ELSE ({m.group(1).strip()}) END"
            ),
            payload,
        )
    if script == "informationschemacomment":
        return re.sub(r"(?i)information_schema", "information_schema/**/", payload)
    if script == "lowercase":
        return re.sub(
            r"[A-Za-z_]+",
            lambda m: m.group(0).lower() if m.group(0).upper() in _SQL_KEYWORDS else m.group(0),
            payload,
        )
    if script == "multiplespaces":
        return _multiple_spaces(payload)
    if script == "percentage":
        return _percentage(payload)
    if script == "plus2concat":
        return _plus_to_concat(payload, fn=False)
    if script == "plus2fnconcat":
        return _plus_to_concat(payload, fn=True)
    if script == "randomcomments":
        return _random_comments(payload)
    if script == "sp_password":
        return payload if payload.lower().endswith("sp_password") else payload + "-- sp_password"
    if script == "symboliclogical":
        return re.sub(r"(?i)\bAND\b", "%26%26", re.sub(r"(?i)\bOR\b", "%7C%7C", payload))
    if script == "unionalltounion":
        return re.sub(r"(?i)UNION\s+ALL\s+SELECT", "UNION SELECT", payload)
    if script == "unmagicquotes":
        return payload.replace("'", "%bf%27").replace("-- ", "%23")
    if script == "uppercase":
        return re.sub(
            r"[A-Za-z_]+",
            lambda m: m.group(0).upper() if m.group(0).upper() in _SQL_KEYWORDS else m.group(0),
            payload,
        )
    if script == "versionedkeywords":
        return _wrap_keywords(payload)
    if script == "versionedmorekeywords":
        return _wrap_keywords(payload, prefix="/*!50000 ", suffix="*/")
    if script == "reverse":
        return payload[::-1]
    if script == "randomcase":
        return "".join(ch.upper() if idx % 2 else ch.lower() for idx, ch in enumerate(payload))
    if script == "space2comment":
        return payload.replace(" ", "/**/")
    if script == "space2plus":
        return payload.replace(" ", "+")
    if script == "space2tab":
        return payload.replace(" ", "\t")
    return payload


def _apply_rust_script(script: str, payload: str) -> str | None:
    rust = load_rust_core()
    apply_tamper = rust.get("apply_tamper")
    if not callable(apply_tamper):
        return None
    try:
        candidate = apply_tamper(script, payload)
        return candidate if isinstance(candidate, str) else None
    except EvasionError:
        return None


def tamper_payload(
    session: ScanSession, payload: str, *, body_format: str | None = None, blocked: bool = False
) -> tuple[str, dict[str, str], list[str]]:
    transformed = payload
    headers: dict[str, str] = {}
    applied: list[str] = []
    for script in resolve_tamper_pipeline(session, blocked=blocked, body_format=body_format):
        if script in _HEADER_MUTATORS:
            _mutate_headers(script, transformed, headers)
            applied.append(script)
            continue
        candidate = _apply_rust_script(script, transformed) or _apply_python_script(
            script, transformed
        )
        if candidate != transformed:
            transformed = candidate
            applied.append(script)
    return transformed, headers, applied


def _mutate_object(
    value: Any, session: ScanSession, *, body_format: str, blocked: bool
) -> tuple[Any, dict[str, str], list[str]]:
    if isinstance(value, dict):
        headers: dict[str, str] = {}
        applied: list[str] = []
        result: dict[str, Any] = {}
        for key, child in value.items():
            result[key], extra_headers, scripts = _mutate_object(
                child, session, body_format=body_format, blocked=blocked
            )
            headers.update(extra_headers)
            applied.extend(scripts)
        return result, headers, _dedupe(applied)
    if isinstance(value, list):
        headers: dict[str, str] = {}
        applied: list[str] = []
        items = []
        for child in value:
            item, extra_headers, scripts = _mutate_object(
                child, session, body_format=body_format, blocked=blocked
            )
            items.append(item)
            headers.update(extra_headers)
            applied.extend(scripts)
        return items, headers, _dedupe(applied)
    if isinstance(value, str):
        return tamper_payload(session, value, body_format=body_format, blocked=blocked)
    return value, {}, []


def _duplicate_query_params(url: str) -> str:
    parsed = urlparse(url)
    query = parse_qsl(parsed.query, keep_blank_values=True)
    if not query:
        return url
    duplicated = [*query, *query]
    return urlunparse(parsed._replace(query=urlencode(duplicated, doseq=True)))


def _duplicate_form_data(data: Any) -> str | None:
    if not isinstance(data, dict) or not data:
        return None
    pairs = []
    for key, value in data.items():
        pairs.append((key, value))
        pairs.append((key, value))
    return urlencode(pairs, doseq=True)


def _xml_entities(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _xml_entities(child) for key, child in value.items()}
    if isinstance(value, list):
        return [_xml_entities(child) for child in value]
    if isinstance(value, str):
        return "".join(f"&#x{ord(ch):x};" for ch in value)
    return value


def build_retry_candidates(
    session: ScanSession,
    *,
    url: str,
    data: Any,
    headers: dict[str, str],
    method: str,
    body_format: str,
    multipart_fields: set[str] | None = None,
) -> list[AdaptiveCandidate]:
    mutated_data, tamper_headers, pipeline = _mutate_object(
        data, session, body_format=body_format, blocked=True
    )
    mutated_headers = {**headers, **tamper_headers}
    candidates = [
        AdaptiveCandidate(
            name="tamper-pipeline",
            url=url,
            data=mutated_data,
            headers=mutated_headers,
            body_format=body_format,
            pipeline=tuple(pipeline),
        )
    ]
    if urlparse(url).query:
        candidates.append(
            AdaptiveCandidate(
                name="http-parameter-pollution",
                url=_duplicate_query_params(url),
                data=data,
                headers=headers,
                body_format=body_format,
                notes=("duplicate-query-params",),
            )
        )
    if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} and body_format == "form":
        duplicated = _duplicate_form_data(mutated_data)
        if duplicated:
            hpp_headers = dict(headers)
            hpp_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            candidates.append(
                AdaptiveCandidate(
                    name="form-hpp",
                    url=url,
                    data=duplicated,
                    headers=hpp_headers,
                    body_format="form",
                    notes=("duplicate-form-params",),
                )
            )
    if body_format == "json" and isinstance(mutated_data, dict):
        entity_data, entity_headers, entity_scripts = _mutate_object(
            data, session, body_format="json", blocked=True
        )
        candidates.append(
            AdaptiveCandidate(
                name="json-unicode-escape",
                url=url,
                data=entity_data,
                headers={**headers, **entity_headers},
                body_format="json",
                pipeline=tuple(entity_scripts),
            )
        )
    if body_format == "xml":
        candidates.append(
            AdaptiveCandidate(
                name="xml-entity-encoding",
                url=url,
                data=_xml_entities(mutated_data),
                headers=headers,
                body_format="xml",
                notes=("xml-entity-encoding",),
            )
        )
    if method.upper() in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        candidates.append(
            AdaptiveCandidate(
                name="fragmented-request",
                url=url,
                data=mutated_data,
                headers=mutated_headers,
                body_format=body_format,
                transport="fragmented",
                pipeline=tuple(pipeline),
                notes=("transport-fragmentation",),
            )
        )
    deduped: list[AdaptiveCandidate] = []
    seen: set[tuple[str, str, str, str]] = set()
    for candidate in candidates[: max(1, int(session.config.tamper_retry_budget or 1))]:
        fingerprint = (
            candidate.name,
            candidate.url,
            json.dumps(candidate.data, sort_keys=True, default=str),
            candidate.transport,
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        deduped.append(candidate)
    return deduped


def record_adaptive_result(
    session: ScanSession, candidate: AdaptiveCandidate, *, blocked: bool, status_code: int | None
) -> None:
    metadata = session.metadata.setdefault("adaptive_waf", {})
    if not isinstance(metadata, dict):
        return
    attempts = metadata.setdefault("attempts", [])
    if not isinstance(attempts, list):
        return
    attempts.append(
        {
            "name": candidate.name,
            "transport": candidate.transport,
            "pipeline": list(candidate.pipeline),
            "notes": list(candidate.notes),
            "status_code": status_code,
            "blocked": blocked,
        }
    )
    metadata["applied"] = True


def detect_ml_waf(session: ScanSession, response: dict[str, Any]) -> tuple[bool, float]:
    """Detect if WAF is ML-based using heuristic analysis."""
    return ml_bypass.detect_ml_waf(session, response)


def apply_polymorphic_encoding(
    session: ScanSession, payload: str, chain_length: int | None = None
) -> str:
    """Apply polymorphic encoding with dynamic chains."""
    return polymorphic.generate_polymorphic_payload(payload, chain_length)


def apply_behavioral_evasion(session: ScanSession, headers: dict[str, str]) -> dict[str, str]:
    """Apply behavioral evasion (timing, header normalization)."""
    return behavioral.normalize_request_headers(headers)


def apply_protocol_evasion(
    session: ScanSession, request: str, payload: str, technique: str = "cl_te"
) -> str:
    """Apply protocol-level evasion (smuggling, fragmentation)."""
    return protocol.apply_request_smuggling(request, payload, technique)


def smart_encoding_optimizer(
    session: ScanSession, pipeline: list[str], success_rate: float
) -> list[str]:
    """Optimize encoding chain based on WAF response feedback."""
    optimizer = polymorphic.ChainOptimizer()

    # Convert pipeline to EncodingChain
    chain = polymorphic.EncodingChain(operations=tuple(pipeline))

    # Record performance
    if success_rate > 0.5:
        chain.record_success()
    else:
        chain.record_failure()

    # Get optimal chain
    optimal = optimizer.get_optimal_chain()
    if optimal:
        return list(optimal.operations)

    return pipeline


def adaptive_escalation_with_feedback(
    session: ScanSession, payload: str, blocked: bool, response: dict[str, Any] | None = None
) -> str:
    """Escalate tamper scripts based on WAF response patterns."""
    if not blocked:
        return payload

    # Analyze response if available
    if response:
        is_ml, confidence = ml_bypass.detect_ml_waf(session, response)

        if is_ml and confidence > 0.5:
            # Use ML-specific bypass
            return ml_bypass.generate_adversarial_payload(payload, mutation_strength=0.4)

        # Use pattern analysis
        pattern_analysis = ml_bypass.analyze_waf_pattern(response)
        if pattern_analysis.get("timing_variance", 0) > 50:
            # Use frequency-based mutations
            heuristic = ml_bypass.AdversarialHeuristic()
            return heuristic.generate_frequency_based_payload(payload)

    # Default escalation: apply polymorphic encoding
    return polymorphic.generate_polymorphic_payload(payload, mutation_count=2)


def automated_bypass_discovery(
    session: ScanSession, payload: str, max_attempts: int = 10
) -> list[str]:
    """Discover effective bypasses using automated testing."""
    generator = ml_bypass.BypassGenerator()
    bypass_candidates = generator.generate_bypass(session, payload)

    # Limit candidates based on max_attempts
    return bypass_candidates[:max_attempts]
