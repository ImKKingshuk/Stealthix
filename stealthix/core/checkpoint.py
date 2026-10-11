from __future__ import annotations

import json
import os
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from stealthix.core.models import Finding
from stealthix.core.session import ScanSession

CHECKPOINT_KIND = "stealthix.scan.checkpoint"
CHECKPOINT_VERSION = 1
_RUNTIME_EXCLUDE_KEYS = {"checkpoint_manager", "checkpoint_resume_payload", "checkpoint_last_state"}


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    if isinstance(value, set):
        return [_json_safe(item) for item in sorted(value, key=str)]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    try:
        json.dumps(value)
    except TypeError:
        return str(value)
    return value


def serialize_finding(finding: Finding) -> dict[str, Any]:
    return asdict(finding)


def deserialize_finding(payload: dict[str, Any]) -> Finding:
    return Finding(
        kind=str(payload.get("kind") or ""),
        target=str(payload.get("target") or ""),
        details=dict(payload.get("details") or {}),
        parameter=str(payload["parameter"]).strip()
        if payload.get("parameter") not in (None, "")
        else None,
        location=str(payload["location"]).strip()
        if payload.get("location") not in (None, "")
        else None,
    )


def serialize_findings(findings: list[Finding]) -> list[dict[str, Any]]:
    return [serialize_finding(finding) for finding in findings]


def deserialize_findings(payload: list[dict[str, Any]] | None) -> list[Finding]:
    return [deserialize_finding(item) for item in payload or [] if isinstance(item, dict)]


def snapshot_session(session: ScanSession) -> dict[str, Any]:
    runtime = {
        str(key): _json_safe(value)
        for key, value in session.runtime.items()
        if key not in _RUNTIME_EXCLUDE_KEYS
    }
    return session.to_payload(include_runtime=False) | {"runtime": runtime}


def restore_session(payload: dict[str, Any]) -> ScanSession:
    return ScanSession.from_payload(payload)


def load_checkpoint(path: str | Path) -> dict[str, Any]:
    checkpoint_path = Path(path)
    if not checkpoint_path.is_file():
        raise FileNotFoundError(f"Checkpoint file not found: {checkpoint_path}")
    with checkpoint_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"Malformed checkpoint file (not a JSON object): {checkpoint_path}")
    if payload.get("kind") != CHECKPOINT_KIND:
        raise ValueError(f"Unsupported checkpoint file: {checkpoint_path}")
    if int(payload.get("version", 0)) != CHECKPOINT_VERSION:
        raise ValueError(f"Unsupported checkpoint version in {checkpoint_path}")
    return payload


@dataclass
class CheckpointManager:
    path: Path
    interval_seconds: float = 60.0
    _last_saved_at: float = field(default=0.0, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path = Path(self.path)
        self.interval_seconds = max(0.0, float(self.interval_seconds or 0.0))

    def should_save(self, *, force: bool = False) -> bool:
        if force:
            return True
        if self.interval_seconds <= 0:
            return False
        return (time.monotonic() - self._last_saved_at) >= self.interval_seconds

    def _atomic_write(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
        tmp_fd, tmp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
        )
        try:
            with os.fdopen(tmp_fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.path)
        finally:
            if os.path.exists(tmp_name):
                os.unlink(tmp_name)

    def save_payload(self, payload: dict[str, Any], *, force: bool = False) -> bool:
        if not self.should_save(force=force):
            return False
        self._atomic_write(payload)
        self._last_saved_at = time.monotonic()
        return True

    def build_payload(
        self,
        session: ScanSession,
        *,
        mode: str,
        status: str,
        state: dict[str, Any],
        input_context: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        return {
            "kind": CHECKPOINT_KIND,
            "version": CHECKPOINT_VERSION,
            "saved_at": _now_iso(),
            "mode": str(mode),
            "status": str(status),
            "session": snapshot_session(session),
            "state": _json_safe(state),
            "input_context": _json_safe(input_context or {}),
            "error": _json_safe(error) if error else None,
        }

    def save_snapshot(
        self,
        session: ScanSession,
        *,
        mode: str,
        status: str,
        state: dict[str, Any],
        input_context: dict[str, Any] | None = None,
        error: dict[str, Any] | None = None,
        force: bool = False,
    ) -> bool:
        payload = self.build_payload(
            session,
            mode=mode,
            status=status,
            state=state,
            input_context=input_context,
            error=error,
        )
        return self.save_payload(payload, force=force)


__all__ = [
    "CHECKPOINT_KIND",
    "CHECKPOINT_VERSION",
    "CheckpointManager",
    "deserialize_findings",
    "load_checkpoint",
    "restore_session",
    "serialize_findings",
    "snapshot_session",
]
