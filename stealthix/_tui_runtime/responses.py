from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def timestamp() -> str:
    return datetime.now(UTC).isoformat()


def normalize_response(
    *,
    ok: bool,
    message: str | None = None,
    data: Any | None = None,
    job: Any | None = None,
    logs: list[dict[str, str]] | None = None,
    error: str | None = None,
) -> dict[str, Any]:
    return {
        "ok": ok,
        "message": message,
        "data_json": json.dumps(data, sort_keys=True) if data is not None else None,
        "job_json": json.dumps(job, sort_keys=True) if job is not None else None,
        "logs": logs,
        "error": error,
    }


def ok_response(
    message: str | None = None,
    *,
    data: Any | None = None,
    job: Any | None = None,
    logs: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    return normalize_response(ok=True, message=message, data=data, job=job, logs=logs)


def error_response(error: str, *, message: str | None = None) -> dict[str, Any]:
    return normalize_response(ok=False, message=message or error, error=error)


def output_dir() -> Path:
    override = (os.environ.get("STEALTHIX_OUTPUT_DIR") or "").strip()
    path = Path(override).expanduser().resolve() if override else (Path.cwd() / "output").resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path
