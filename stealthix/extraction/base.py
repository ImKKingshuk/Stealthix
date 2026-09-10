from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from stealthix.core.errors import ExtractionError, NetworkError
from stealthix.core.http import make_request
from stealthix.core.session import ScanSession
from stealthix.core.targeting import InjectionPoint, apply_payload, discover_injection_points
from stealthix.detection.rest_api import method_uses_body
from stealthix.utils.bypass import apply_waf_bypass


def _make_request(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    method: str | None = None,
) -> tuple[str, float]:
    return make_request(session, url, data, method)


def _apply_param(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True, safe=":/")
    return urlunparse(parsed._replace(query=new_query))


def _prepare_payload(session: ScanSession, payload: str) -> str:
    return apply_waf_bypass(session, payload)


def _injection_point(session: ScanSession) -> InjectionPoint:
    meta = session.metadata.get("injection")
    if isinstance(meta, dict):
        name = str(meta.get("parameter") or "").strip()
        location = str(meta.get("location") or "").strip()
        if name and location:
            return InjectionPoint(name=name, location=location)
    points = discover_injection_points(session)
    if points:
        return points[0]
    if method_uses_body(session.config.method):
        loc = "json" if session.config.body_format == "json" else "form"
    else:
        loc = "query"
    return InjectionPoint(name="id", location=loc)


def _apply_injection(session: ScanSession, payload: str) -> tuple[str, dict[str, Any] | None]:
    point = _injection_point(session)
    return apply_payload(session, point, payload)


def _get_extraction_profile(session: ScanSession, operation: str) -> dict[str, Any] | None:
    plugin = session.metadata.get("plugin")
    if not isinstance(plugin, dict):
        return None
    profiles = plugin.get("extraction_profiles")
    if not isinstance(profiles, dict):
        return None
    profile = profiles.get(operation)
    if not isinstance(profile, dict):
        return None
    return profile


def _plugin_family(session: ScanSession) -> str:
    plugin = session.metadata.get("plugin")
    family = plugin.get("family") if isinstance(plugin, dict) else None
    if isinstance(family, str) and family.strip():
        return family.strip().lower()
    dbms = str(session.config.dbms or "").strip().lower()
    if dbms in {"mongodb", "couchdb", "redis", "cassandra", "firebase", "dynamodb"}:
        return "nosql"
    if dbms in {"cockroachdb", "tidb", "yugabytedb", "spanner"}:
        return "newsql"
    return "sql"


def _preferred_extraction_techniques(session: ScanSession) -> list[str]:
    order: list[str] = []
    seen: set[str] = set()

    def add(items: list[str]) -> None:
        for item in items:
            normalized = str(item or "").strip().lower()
            if normalized and normalized not in seen:
                seen.add(normalized)
                order.append(normalized)

    detected = session.metadata.get("detected_techniques")
    if isinstance(detected, list):
        add([str(item) for item in detected])

    config = str(session.config.technique or "").upper()
    config_map = {"U": "union", "B": "boolean", "T": "time"}
    add([config_map[ch] for ch in config if ch in config_map])

    plugin = session.metadata.get("plugin")
    raw = plugin.get("preferred_techniques") if isinstance(plugin, dict) else ""
    if isinstance(raw, str):
        add([config_map[ch] for ch in raw.upper() if ch in config_map])

    fallback = (
        ["union", "boolean", "time"] if _plugin_family(session) != "nosql" else ["boolean", "time"]
    )
    add(fallback)
    return order


def _merge_results(primary: dict[str, Any], fallback: dict[str, Any]) -> dict[str, Any]:
    responses = (
        cast(list[Any], primary.get("responses"))
        if isinstance(primary.get("responses"), list)
        else []
    )
    payloads = (
        cast(list[Any], primary.get("payloads"))
        if isinstance(primary.get("payloads"), list)
        else []
    )
    warnings = (
        cast(list[Any], primary.get("warnings"))
        if isinstance(primary.get("warnings"), list)
        else []
    )
    fallback_responses = (
        cast(list[Any], fallback.get("responses"))
        if isinstance(fallback.get("responses"), list)
        else []
    )
    fallback_payloads = (
        cast(list[Any], fallback.get("payloads"))
        if isinstance(fallback.get("payloads"), list)
        else []
    )
    fallback_warnings = (
        cast(list[Any], fallback.get("warnings"))
        if isinstance(fallback.get("warnings"), list)
        else []
    )
    fallback["responses"] = responses + fallback_responses
    fallback["payloads"] = payloads + fallback_payloads
    all_warnings = warnings + fallback_warnings
    fallback["warnings"] = _dedupe_strings(all_warnings)
    return fallback


def _dedupe_strings(values: list[str]) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = str(value).strip()
        if item and item not in seen:
            seen.add(item)
            output.append(item)
    return output


def _error_hints(body: str) -> list[str]:
    error_patterns = [
        r"SQLSTATE\[[0-9A-Z]+\].{0,200}",
        r"ORA-\d{4,6}.{0,200}",
        r"Warning:\s*mysql.{0,200}",
        r"syntax error.{0,200}",
        r"unclosed quotation mark.{0,200}",
    ]
    matches: list[str] = []
    for pattern in error_patterns:
        matches.extend(re.findall(pattern, body, flags=re.IGNORECASE))
    return _dedupe_strings(matches)


def _looks_like_db_error(body: str) -> bool:
    stripped = (body or "").strip()
    return bool(stripped) and len(stripped) <= 2000 and bool(_error_hints(body))


def _response_entry(
    target: str, payload: str, body: str, elapsed: float, limit: int = 5000
) -> dict[str, Any]:
    return {
        "target": target,
        "payload": payload,
        "elapsed": elapsed,
        "body": body[:limit],
        "truncated": len(body) > limit,
        "error_hints": _error_hints(body),
    }


def _result_base(
    session: ScanSession, operation: str, payloads: list[str] | None = None
) -> dict[str, Any]:
    dbms = (session.config.dbms or "").lower() or "auto"
    return {
        "operation": operation,
        "dbms": dbms,
        "payloads": payloads,
        "responses": [],
        "selected_payload": None,
        "success": False,
        "count": 0,
        "warnings": [],
    }


def _record_success(result: dict[str, Any], payload: str) -> None:
    if result.get("selected_payload") is None:
        result["selected_payload"] = payload
    result["success"] = True


def _finalize_collection_result(result: dict[str, Any], key: str) -> dict[str, Any]:
    values = result.get(key) if isinstance(result.get(key), list) else []
    normalized = _dedupe_strings([str(item) for item in values] if isinstance(values, list) else [])
    result[key] = normalized
    result["count"] = len(normalized)
    result["success"] = bool(normalized)
    return result


def _finalize_text_result(result: dict[str, Any], key: str) -> dict[str, Any]:
    value = str(result.get(key) or "")
    result[key] = value
    meaningful = bool(value.strip()) and not _looks_like_db_error(value)
    result["count"] = 1 if (result.get("success") or meaningful) else 0
    result["success"] = bool(result.get("success")) or meaningful
    if value.strip() and not result["success"] and _looks_like_db_error(value):
        warnings = result.get("warnings") if isinstance(result.get("warnings"), list) else []
        if isinstance(warnings, list):
            warnings.append(
                "Last response looked like a database error rather than extracted content."
            )
        result["warnings"] = _dedupe_strings(warnings if isinstance(warnings, list) else [])
    return result


def _finalize_rows_result(result: dict[str, Any], key: str) -> dict[str, Any]:
    rows = result.get(key) if isinstance(result.get(key), list) else []
    deduped: list[Any] = []
    seen: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        marker = json.dumps(row, sort_keys=True, default=str)
        if marker not in seen:
            seen.add(marker)
            deduped.append(row)
    result[key] = deduped
    result["count"] = len(deduped)
    result["success"] = bool(deduped)
    return result


def _extract_rows(
    body: str, columns: list[str]
) -> list[dict[str, Any] | list[Any] | str | list[list[str]]]:
    stripped = body.strip()
    if not stripped:
        return []
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(stripped)
            if isinstance(payload, dict):
                if isinstance(payload.get("rows"), list):
                    payload = payload["rows"]
                elif columns and all(column in payload for column in columns):
                    return [{column: payload.get(column) for column in columns}]
            if isinstance(payload, list):
                rows: list[dict[str, Any] | list[Any] | str] = []
                for item in payload:
                    if isinstance(item, dict):
                        if columns:
                            rows.append({column: item.get(column) for column in columns})
                        else:
                            rows.append(item)
                    elif isinstance(item, list):
                        rows.append(item)
                    elif isinstance(item, (str, int, float, bool)):
                        rows.append(str(item))
                if rows:
                    return rows
        except ExtractionError:
            pass
    separators = ["|", "\t", ","]
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    for separator in separators:
        parsed_rows: list[list[str]] = []
        for line in lines:
            if separator not in line:
                continue
            parts = [part.strip() for part in line.split(separator)]
            if columns and len(parts) != len(columns):
                continue
            parsed_rows.append(parts)
        if parsed_rows:
            if columns:
                return [
                    dict(zip(columns, row, strict=False))
                    for row in parsed_rows
                    if len(row) == len(columns)
                ]
            return cast(list[dict[str, Any] | list[Any] | str | list[list[str]]], parsed_rows)
    if len(columns) == 1 and lines:
        return [{columns[0]: line} for line in lines]
    return []


def _extract_values(body: str, patterns: list[str] | None = None) -> list[str]:
    sources: list[str] = []
    structured = False
    stripped = body.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        try:
            payload = json.loads(body)
            pieces: list[str] = []

            def walk(prefix: str, obj: Any) -> None:
                if obj is None:
                    return
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        key = f"{prefix}.{k}" if prefix else str(k)
                        walk(key, v)
                    return
                if isinstance(obj, list):
                    for idx, v in enumerate(obj):
                        walk(f"{prefix}[{idx}]" if prefix else f"[{idx}]", v)
                    return
                if isinstance(obj, (str, int, float, bool)):
                    pieces.append(f"{prefix} {obj}")

            walk("", payload)
            if pieces:
                structured = True
                sources.append("\n".join(pieces))
        except ExtractionError:
            pass
    if "<" in body and len(body) <= 1_000_000:
        try:
            root = DefusedET.fromstring(body)
            xml_pieces: list[str] = []
            for elem in root.iter():
                tag = (elem.tag or "").strip()
                text = (elem.text or "").strip()
                if tag and text:
                    xml_pieces.append(f"{tag} {text}")
                for k, v in elem.attrib.items():
                    if k and v:
                        xml_pieces.append(f"{k} {v}")
            if xml_pieces:
                structured = True
                sources.append("\n".join(xml_pieces))
        except (ParseError, DefusedXmlException):
            pass  # Not valid XML, skip
        except ExtractionError:
            pass
        try:

            class _TextCollector(HTMLParser):
                def __init__(self) -> None:
                    super().__init__()
                    self._chunks: list[str] = []

                def handle_data(self, data: str) -> None:
                    text = (data or "").strip()
                    if text:
                        self._chunks.append(text)

                def text(self) -> str:
                    return " ".join(self._chunks)

            collector = _TextCollector()
            collector.feed(body)
            text = collector.text()
            if text:
                structured = True
                sources.append(text)
        except ExtractionError:
            pass
    if not structured:
        sources.append(body)

    hints = _error_hints(body)
    if hints:
        sources.append("\n".join(hints))

    results: list[str] = []
    for source in sources:
        for pattern in patterns if isinstance(patterns, list) else []:
            for match in re.findall(pattern, source, flags=re.IGNORECASE):
                if isinstance(match, tuple):
                    results.extend([item for item in match if item])
                else:
                    results.append(match)
    deduped = []
    for item in results:
        if item not in deduped:
            deduped.append(item)
    return deduped
