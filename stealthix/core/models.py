"""Core data models for Stealthix.

This module contains the core data classes used across the application.
Separated from engine.py to avoid circular imports with detection modules.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """Represents a single vulnerability finding."""

    kind: str
    target: str
    details: dict[str, Any] = field(default_factory=dict)
    parameter: str | None = None
    location: str | None = None


@dataclass(frozen=True)
class TargetParam:
    name: str
    location: str
    type: str = "string"

    @property
    def kind(self) -> str:
        return self.type


@dataclass
class ScanResult:
    """Contains all findings from a scan session."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
