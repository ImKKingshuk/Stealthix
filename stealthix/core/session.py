from __future__ import annotations

import logging
import os
import threading
import time
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

import structlog

from stealthix.core.config_models import SessionConfigModel
from stealthix.core.control import ScanControl
from stealthix.core.creds import CredentialStore
from stealthix.core.errors import StealthixError
from stealthix.core.history import RequestHistory

logger = structlog.get_logger(__name__)

# Re-export for backward compatibility
SessionConfig = SessionConfigModel


_COUNTER_KEYS = {"blocked_responses", "retry_count", "rate_limited_responses"}
_LATEST_WINS_KEYS = {"last_status", "last_waf_hints", "transport"}
_REDACTED = "***REDACTED***"


def _restore_redacted(value: Any) -> Any:
    if value == _REDACTED:
        return None
    if isinstance(value, dict):
        return {key: _restore_redacted(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_restore_redacted(item) for item in value]
    return value


def _restore_config_payload(payload: dict[str, Any]) -> dict[str, Any]:
    restored = _restore_redacted(payload)
    if not isinstance(restored, dict):
        return {}
    for key in ("headers", "cookies"):
        if isinstance(restored.get(key), dict):
            restored[key] = {
                str(item_key): str(item_value)
                for item_key, item_value in restored[key].items()
                if item_value is not None
            }
    return restored


def _merge_value(current: Any, incoming: Any, *, key: str | None = None) -> Any:
    if isinstance(current, dict) and isinstance(incoming, dict):
        _merge_mapping(current, incoming)
        return current
    if isinstance(current, list) and isinstance(incoming, list):
        for item in incoming:
            if item not in current:
                current.append(deepcopy(item))
        return current
    if isinstance(current, bool) and isinstance(incoming, bool):
        return current or incoming
    if (
        key in _COUNTER_KEYS
        and isinstance(current, (int, float))
        and isinstance(incoming, (int, float))
    ):
        return current + incoming
    if key in _LATEST_WINS_KEYS:
        return deepcopy(incoming)
    if current in (None, "", [], {}):
        return deepcopy(incoming)
    return current


def _merge_mapping(target: dict[str, Any], source: dict[str, Any]) -> None:
    for key, value in source.items():
        if key not in target:
            target[key] = deepcopy(value)
            continue
        target[key] = _merge_value(target[key], value, key=key)


@dataclass
class ScanSession:
    config: SessionConfig
    metadata: dict[str, Any] = field(default_factory=dict)
    history: RequestHistory = field(default_factory=RequestHistory)
    creds: CredentialStore = field(default_factory=CredentialStore)
    control: ScanControl = field(default_factory=ScanControl)
    runtime: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    _metadata_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def _safe_metadata_update(self, key: str, value: Any) -> None:
        """Thread-safe metadata update."""
        with self._metadata_lock:
            self.metadata[key] = value

    def _safe_metadata_get(self, key: str, default: Any = None) -> Any:
        """Thread-safe metadata get."""
        with self._metadata_lock:
            return self.metadata.get(key, default)

    def _safe_metadata_merge(self, other: dict[str, Any]) -> None:
        """Thread-safe metadata merge."""
        with self._metadata_lock:
            _merge_mapping(self.metadata, other)

    def clone_for_worker(self) -> ScanSession:
        with self._metadata_lock:
            metadata_copy = deepcopy(self.metadata)
        return ScanSession(
            config=SessionConfig.from_dict(self.config.to_dict()),
            metadata=metadata_copy,
            history=self.history,
            creds=CredentialStore.from_dict(self.creds.to_dict(include_secrets=True)),
            control=self.control,
            runtime={},
        )

    def merge_worker_state(self, worker: ScanSession) -> None:
        self._safe_metadata_merge(worker.metadata)
        self.config.cookies.update(deepcopy(worker.config.cookies))
        self.config.headers.update(deepcopy(worker.config.headers))
        if worker.config.auth_token:
            self.config.auth_token = worker.config.auth_token
        if worker.config.auth_type:
            self.config.auth_type = worker.config.auth_type
        if worker.config.auth_config:
            current_auth_config = (
                self.config.auth_config if isinstance(self.config.auth_config, dict) else {}
            )
            _merge_mapping(current_auth_config, worker.config.auth_config)
            self.config.auth_config = current_auth_config
        for name, value in worker.creds.secrets.items():
            self.creds.secrets.setdefault(name, value)

    def refresh_auth(self, *, force: bool = True, reason: str | None = None) -> bool:
        from stealthix.core.auth import refresh_auth

        return refresh_auth(self, force=force, reason=reason)

    def to_payload(
        self,
        *,
        include_runtime: bool = False,
        include_secrets: bool = False,
        redact_config: bool = True,
    ) -> dict[str, Any]:
        config = self.config.to_dict_redacted() if redact_config else self.config.to_dict()
        payload = {
            "config": config,
            "metadata": deepcopy(self.metadata),
            "history": self.history.to_list(),
            "creds": self.creds.to_dict(
                include_secrets=include_secrets, redacted=not include_secrets
            ),
            "secrets_redacted": not include_secrets or redact_config,
        }
        if include_runtime:
            payload["runtime"] = deepcopy(self.runtime)
        return payload

    def to_private_payload(self, *, include_runtime: bool = False) -> dict[str, Any]:
        return self.to_payload(
            include_runtime=include_runtime,
            include_secrets=True,
            redact_config=False,
        )

    @staticmethod
    def from_payload(payload: dict[str, Any]) -> ScanSession:
        config_payload = _restore_config_payload(payload["config"])
        config = SessionConfig.from_dict(config_payload)
        session = ScanSession(config=config, metadata=deepcopy(payload.get("metadata", {})))
        session.history = RequestHistory.from_list(payload.get("history", []))
        session.creds = CredentialStore.from_dict(payload.get("creds", {}))
        if isinstance(payload.get("runtime"), dict):
            session.runtime = deepcopy(payload["runtime"])
        return session

    def save(self, path: str, *, include_secrets: bool = True) -> None:
        import json

        payload = self.to_payload(
            include_secrets=include_secrets, redact_config=not include_secrets
        )
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)

    @staticmethod
    def load(path: str) -> ScanSession:
        import json

        with open(path, encoding="utf-8") as handle:
            payload = json.load(handle)
        return ScanSession.from_payload(payload)
