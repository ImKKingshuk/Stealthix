from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qs, urlparse

from stealthix.workflows.requests import RequestSpec

_INTERESTING_NAME_RE = re.compile(
    r"(id|uid|user|account|tenant|q|query|search|filter|sort|where|select|token|redirect|url)$",
    re.IGNORECASE,
)
_SQLISH_VALUE_RE = re.compile(
    r"('|--|/\*|\b(or|and|union|select|sleep|benchmark)\b)", re.IGNORECASE
)
_NOSQLISH_VALUE_RE = re.compile(r"(\$ne|\$gt|\$where|\{\s*\"\$)", re.IGNORECASE)
_STATIC_EXT_RE = re.compile(r"\.(?:css|js|png|jpg|jpeg|gif|svg|ico|woff2?)$", re.IGNORECASE)
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key"}


@dataclass(frozen=True)
class InjectionHint:
    name: str
    location: str
    value_excerpt: str
    reasons: list[str]
    confidence: float


def passive_injection_hints(requests: RequestSpec | Iterable[RequestSpec]) -> list[InjectionHint]:
    specs = [requests] if isinstance(requests, RequestSpec) else list(requests)
    hints: list[InjectionHint] = []
    for spec in specs:
        hints.extend(_hints_for_spec(spec))
    return _dedupe_hints(hints)


def _hints_for_spec(spec: RequestSpec) -> list[InjectionHint]:
    hints: list[InjectionHint] = []
    parsed = urlparse(spec.url)
    if _STATIC_EXT_RE.search(parsed.path):
        return hints
    for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
        hints.append(_score_value(str(name), values[0] if values else "", "query"))
    body_data = spec.data
    if body_data is None and spec.raw_body:
        raw_text = spec.raw_body.strip()
        if raw_text:
            if (raw_text.startswith("{") and raw_text.endswith("}")) or (
                raw_text.startswith("[") and raw_text.endswith("]")
            ):
                import json

                try:
                    body_data = json.loads(raw_text)
                except Exception:
                    body_data = None
            elif "=" in raw_text:
                body_data = {
                    k: v[0] if v else ""
                    for k, v in parse_qs(raw_text, keep_blank_values=True).items()
                }

    for name, value in _body_fields(body_data):
        hints.append(_score_value(name, value, "body"))
    for name, value in spec.cookies.items():
        hints.append(_score_value(str(name), str(value), "cookie"))
    for name, value in spec.headers.items():
        lowered = str(name).lower()
        if lowered in _SENSITIVE_HEADERS:
            continue
        if lowered.startswith("x-") or lowered in {"referer", "origin"}:
            hints.append(_score_value(str(name), str(value), "header"))
    for index, segment in enumerate([part for part in parsed.path.split("/") if part], start=1):
        if segment.isdigit() or _looks_uuid(segment):
            hints.append(
                InjectionHint(
                    name=f"path[{index}]",
                    location="path",
                    value_excerpt=_excerpt(segment),
                    reasons=["identifier-like path segment"],
                    confidence=0.65,
                )
            )
    return [hint for hint in hints if hint.confidence >= 0.35]


def _score_value(name: str, value: Any, location: str) -> InjectionHint:
    text = "" if value is None else str(value)
    reasons: list[str] = []
    score = 0.25
    if _INTERESTING_NAME_RE.search(name):
        reasons.append("interesting parameter name")
        score += 0.25
    if text.isdigit():
        reasons.append("numeric value")
        score += 0.15
    if _looks_uuid(text):
        reasons.append("uuid-like value")
        score += 0.15
    if _SQLISH_VALUE_RE.search(text):
        reasons.append("SQL-like syntax already present")
        score += 0.35
    if _NOSQLISH_VALUE_RE.search(text):
        reasons.append("NoSQL operator-like syntax already present")
        score += 0.35
    if location in {"header", "cookie"}:
        score -= 0.05
    return InjectionHint(
        name=name,
        location=location,
        value_excerpt=_excerpt(text),
        reasons=reasons or ["captured user-controlled value"],
        confidence=min(score, 0.95),
    )


def _body_fields(value: Any, *, prefix: str = "") -> list[tuple[str, Any]]:
    if isinstance(value, dict):
        fields: list[tuple[str, Any]] = []
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            fields.extend(_body_fields(child, prefix=name))
        return fields
    if isinstance(value, list):
        fields = []
        for index, child in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            fields.extend(_body_fields(child, prefix=name))
        return fields
    return [(prefix or "payload", value)] if value not in (None, "") else []


def _looks_uuid(value: str) -> bool:
    text = str(value or "").lower()
    return (
        len(text) == 36 and text.count("-") == 4 and all(ch in "0123456789abcdef-" for ch in text)
    )


def _excerpt(value: str, *, limit: int = 80) -> str:
    text = str(value or "")
    return text if len(text) <= limit else f"{text[: limit - 1]}..."


def _dedupe_hints(hints: list[InjectionHint]) -> list[InjectionHint]:
    seen: set[tuple[str, str]] = set()
    output: list[InjectionHint] = []
    for hint in sorted(hints, key=lambda item: item.confidence, reverse=True):
        key = (hint.location, hint.name)
        if key in seen:
            continue
        seen.add(key)
        output.append(hint)
    return output


__all__ = ["InjectionHint", "passive_injection_hints"]
