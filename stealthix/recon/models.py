"""
Data models for reconnaissance operations.
"""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ReconConfig:
    """Configuration for reconnaissance operations."""

    enabled: bool = True
    tech_enabled: bool = True
    endpoints_enabled: bool = True
    wordlist_path: str | None = None
    max_endpoints: int = 100
    depth: int = 2
    timeout: float | None = None
    use_head_requests: bool = True

    def __post_init__(self):
        """Validate and sanitize configuration values."""
        # Ensure non-negative values
        if self.max_endpoints < 0:
            self.max_endpoints = 100
        if self.depth < 0:
            self.depth = 2
        if self.timeout is not None and self.timeout < 0:
            self.timeout = None


@dataclass
class TechnologyMatch:
    """Represents a detected technology."""

    category: str  # "web_server", "framework", "cms", "cdn_waf", "language", "os", "database"
    name: str
    version: str | None
    confidence: float  # 0.0 to 1.0
    evidence: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "category": self.category,
            "name": self.name,
            "version": self.version,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class DiscoveredEndpoint:
    """Represents a discovered endpoint."""

    url: str
    status_code: int
    response_size: int
    response_time: float
    category: str  # "admin", "api", "backup", "development", "database_admin"
    confidence: float
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "url": self.url,
            "status_code": self.status_code,
            "response_size": self.response_size,
            "response_time": self.response_time,
            "category": self.category,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


@dataclass
class Fingerprint:
    """Technology fingerprint signature."""

    name: str
    category: str
    patterns: list[
        dict[str, Any]
    ]  # {"type": "header|body|cookie|path", "pattern": "...", "weight": 0.8}
    version_patterns: list[dict[str, Any]] | None = None


@dataclass
class Wordlist:
    """Endpoint wordlist with categorization."""

    paths: list[str]
    category: str
    description: str
