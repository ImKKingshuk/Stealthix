from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import tomli
import yaml

from stealthix.core.config_models import SessionConfigModel


def load_config(path: str | Path) -> SessionConfigModel:
    """
    Load configuration from file and return validated Pydantic model.

    Args:
        path: Path to config file (YAML, TOML, or JSON)

    Returns:
        SessionConfigModel with validated configuration

    Raises:
        FileNotFoundError: If config file doesn't exist
        ValueError: If config format is unsupported or validation fails
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(str(path))

    if path.suffix in {".yaml", ".yml"}:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    elif path.suffix == ".toml":
        data = tomli.loads(path.read_text(encoding="utf-8"))
    elif path.suffix == ".json":
        data = json.loads(path.read_text(encoding="utf-8"))
    else:
        raise ValueError(f"Unsupported config format: {path.suffix}")

    return SessionConfigModel(**data)
