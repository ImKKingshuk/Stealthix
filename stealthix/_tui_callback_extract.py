from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from typing import Any

from stealthix._tui_callback_runtime import output_dir, session_from_payload
from stealthix._tui_runtime.responses import error_response, ok_response
from stealthix.extraction import (
    dump_table,
    enumerate_columns,
    enumerate_databases,
    enumerate_tables,
    execute_command,
    extract_hashes,
    read_file,
)
from stealthix.plugins.runtime import apply_plugin
from stealthix.support_matrix import ensure_extraction_supported


def _require_extraction_support(dbms: str | None, operation: str) -> dict[str, Any] | None:
    try:
        ensure_extraction_supported(dbms, operation)
    except ValueError as exc:
        return error_response(str(exc))
    return None


def handle_extract_action(action: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if not action.startswith("extract."):
        return None
    session_payload = params.get("session")
    if not isinstance(session_payload, dict):
        raise ValueError("extract actions require a serialized session")
    session = session_from_payload(session_payload)
    apply_plugin(session)

    if action == "extract.enum_databases":
        if error := _require_extraction_support(session.config.dbms, "databases"):
            return error
        result = enumerate_databases(session)
        return ok_response("Enumerated databases.", data=result)
    if action == "extract.enum_tables":
        if error := _require_extraction_support(session.config.dbms, "tables"):
            return error
        database = str(params.get("database") or "").strip() or None
        result = enumerate_tables(session, database=database)
        return ok_response("Enumerated tables.", data=result)
    if action == "extract.enum_columns":
        if error := _require_extraction_support(session.config.dbms, "columns"):
            return error
        table = str(params.get("table") or "").strip()
        result = enumerate_columns(session, table=table or None)
        return ok_response("Enumerated columns.", data=result)
    if action == "extract.dump_table":
        if error := _require_extraction_support(session.config.dbms, "dump"):
            return error
        table = str(params.get("table") or "").strip()
        columns = [str(item).strip() for item in params.get("columns", []) if str(item).strip()]
        result = dump_table(session, table=table, columns=columns)
        return ok_response("Dumped table.", data=result)
    if action == "extract.read_file":
        if error := _require_extraction_support(session.config.dbms, "files"):
            return error
        path = str(params.get("path") or "").strip()
        result = read_file(session, path)
        return ok_response(f"Read file: {path}", data=result)
    if action == "extract.execute_command":
        if error := _require_extraction_support(session.config.dbms, "os"):
            return error
        command = str(params.get("command") or "").strip()
        result = execute_command(session, command)
        return ok_response(f"Executed command: {command}", data=result)
    if action == "extract.hashes":
        if error := _require_extraction_support(session.config.dbms, "hashes"):
            return error
        result = extract_hashes(session)
        return ok_response("Extracted hashes.", data=result)
    if action == "extract.export_dump":
        dump_payload = params.get("dump")
        if not isinstance(dump_payload, dict):
            return error_response("No dump payload is available to export.")
        export_format = str(params.get("format") or "json").strip().lower()
        table = str(params.get("table") or "dump").replace("/", "_")
        stamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        target = output_dir() / f"stealthix-{table}-{stamp}.{export_format}"
        if export_format == "json":
            target.write_text(json.dumps(dump_payload, indent=2, sort_keys=True), encoding="utf-8")
        elif export_format == "csv":
            rows = dump_payload.get("rows")
            buffer = io.StringIO()
            writer = csv.writer(buffer)
            columns = (
                params.get("columns")
                if isinstance(params.get("columns"), list)
                else dump_payload.get("columns")
            )
            if isinstance(columns, list) and columns:
                writer.writerow([str(column) for column in columns])
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        keys = (
                            [str(column) for column in columns]
                            if isinstance(columns, list) and columns
                            else list(row.keys())
                        )
                        writer.writerow([row.get(key, "") for key in keys])
                    elif isinstance(row, list):
                        writer.writerow(row)
                    else:
                        writer.writerow([row])
            else:
                writer.writerow([dump_payload.get("output") or json.dumps(dump_payload)])
            target.write_text(buffer.getvalue(), encoding="utf-8")
        else:
            return error_response(f"Unsupported export format: {export_format}")
        return ok_response(f"Dump exported to {target}.", data={"path": str(target)})
    return None
