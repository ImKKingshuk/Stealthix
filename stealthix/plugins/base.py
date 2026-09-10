from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Plugin:
    name: str
    family: str
    dbms: str | None = None
    payloads: list[str] = field(default_factory=list)
    fingerprints: list[str] = field(default_factory=list)
    error_signatures: list[str] = field(default_factory=list)
    version_queries: list[str] = field(default_factory=list)
    privilege_checks: list[str] = field(default_factory=list)
    os_queries: list[str] = field(default_factory=list)
    preferred_techniques: str | None = None
    extraction_profiles: dict[str, Any] = field(default_factory=dict)
    is_internal: bool = True

    def apply(self, session: Any) -> dict[str, Any] | None:
        """Optional runtime hook for external plugins."""
        return None
