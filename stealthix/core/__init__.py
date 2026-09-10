"""Stealthix core module."""

__all__ = [
    "Engine",
    "AsyncEngine",
    "Finding",
    "ScanResult",
    "ScanSession",
    "SessionConfig",
    "RequestHistory",
    "CredentialStore",
    "configure_logger",
]

from stealthix.core.creds import CredentialStore
from stealthix.core.history import RequestHistory
from stealthix.core.logger import configure_logger
from stealthix.core.models import Finding, ScanResult
from stealthix.core.session import ScanSession, SessionConfig


def __getattr__(name: str):
    """Lazy import Engine to avoid circular imports."""
    if name == "Engine":
        from stealthix.core.engine import Engine

        return Engine
    if name == "AsyncEngine":
        from stealthix.core.async_engine import AsyncEngine

        return AsyncEngine
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
