from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from stealthix.core.session import SessionConfig

_SAFE_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]+")


def profiles_dir() -> Path:
    override = (os.environ.get("STEALTHIX_PROFILES_DIR") or "").strip()
    if override:
        return Path(override).expanduser().resolve()
    return (Path.home() / ".stealthix" / "profiles").resolve()


def _profile_path(name: str) -> Path:
    cleaned = _SAFE_NAME_RE.sub("_", (name or "").strip()) or "default"
    if not cleaned.endswith(".json"):
        cleaned = f"{cleaned}.json"
    return profiles_dir() / cleaned


def list_profiles() -> list[str]:
    base = profiles_dir()
    if not base.exists():
        return []
    items: list[str] = []
    for p in base.glob("*.json"):
        items.append(p.stem)
    return sorted(set(items))


def save_profile(name: str, config: SessionConfig, metadata: dict[str, Any] | None = None) -> Path:
    base = profiles_dir()
    base.mkdir(parents=True, exist_ok=True)
    path = _profile_path(name)
    payload = {"config": config.model_dump(), "metadata": metadata or {}}
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return path


def load_profile(name: str) -> tuple[SessionConfig, dict[str, Any]]:
    path = _profile_path(name)
    payload = json.loads(path.read_text(encoding="utf-8"))
    config = SessionConfig(**payload["config"])
    metadata = payload.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}
    return config, metadata
