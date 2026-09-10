from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse, urlunparse

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _extract_rows,
    _extract_values,
    _finalize_collection_result,
    _finalize_rows_result,
    _make_request,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)
from stealthix.extraction.nosql_adapters import NoSQLAdapterContext, adapter_for_session


def _backend(session: ScanSession) -> str:
    plugin = session.metadata.get("plugin")
    plugin_name = plugin.get("name") if isinstance(plugin, dict) else None
    return str(session.config.dbms or plugin_name or "").strip().lower()


def _root_url(session: ScanSession, path: str) -> str:
    parsed = urlparse(session.config.base_url)
    normalized = "/" + path.lstrip("/")
    return urlunparse(parsed._replace(path=normalized, params="", query="", fragment=""))


def _request_direct(session: ScanSession, url: str) -> tuple[str, str, float]:
    body, elapsed = _make_request(session, url)
    return url, body, elapsed


def _request_injected(session: ScanSession, payload: str) -> tuple[str, str, float]:
    prepared = _prepare_payload(session, payload)
    if method_uses_body(session.config.method):
        target, data = _apply_injection(session, prepared)
        body, elapsed = _make_request(session, target, data, "POST")
    else:
        target, _ = _apply_injection(session, prepared)
        body, elapsed = _make_request(session, target)
    return target, body, elapsed


def _json_payload(body: str) -> Any | None:
    stripped = body.strip()
    if not stripped or stripped[0] not in "[{":
        return None
    try:
        return json.loads(stripped)
    except Exception:
        return None


def _walk_keys(obj: Any, keys: set[str]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key and not str(key).startswith("_"):
                keys.add(str(key))
            _walk_keys(value, keys)
    elif isinstance(obj, list):
        for item in obj:
            _walk_keys(item, keys)


def _body_keys(body: str) -> list[str]:
    payload = _json_payload(body)
    keys: set[str] = set()
    if payload is not None:
        _walk_keys(payload, keys)
    return sorted(keys)


def _strings_from_json(body: str) -> list[str]:
    payload = _json_payload(body)
    values: list[str] = []

    def walk(obj: Any) -> None:
        if isinstance(obj, dict):
            for value in obj.values():
                walk(value)
            return
        if isinstance(obj, list):
            for item in obj:
                walk(item)
            return
        if isinstance(obj, str) and obj.strip():
            values.append(obj.strip())

    if payload is not None:
        walk(payload)
    return values


def _adapter_context() -> NoSQLAdapterContext:
    return NoSQLAdapterContext(
        result_base=_result_base,
        root_url=_root_url,
        request_direct=_request_direct,
        request_injected=_request_injected,
        json_payload=_json_payload,
        body_keys=_body_keys,
        strings_from_json=_strings_from_json,
        extract_values=_extract_values,
        extract_rows=_extract_rows,
        response_entry=_response_entry,
        record_success=_record_success,
        finalize_collection_result=_finalize_collection_result,
        finalize_rows_result=_finalize_rows_result,
    )


def enumerate_databases_nosql(session: ScanSession) -> dict[str, Any]:
    return adapter_for_session(session).enumerate_databases(session, _adapter_context())


def enumerate_tables_nosql(session: ScanSession, *, database: str | None = None) -> dict[str, Any]:
    return adapter_for_session(session).enumerate_tables(
        session, _adapter_context(), database=database
    )


def enumerate_columns_nosql(
    session: ScanSession, *, table: str | None = None, database: str | None = None
) -> dict[str, Any]:
    return adapter_for_session(session).enumerate_columns(
        session, _adapter_context(), table=table, database=database
    )


def dump_table_nosql(
    session: ScanSession, *, table: str, columns: list[str], database: str | None = None
) -> dict[str, Any]:
    return adapter_for_session(session).dump_table(
        session, _adapter_context(), table=table, columns=columns, database=database
    )


__all__ = [
    "dump_table_nosql",
    "enumerate_columns_nosql",
    "enumerate_databases_nosql",
    "enumerate_tables_nosql",
]
