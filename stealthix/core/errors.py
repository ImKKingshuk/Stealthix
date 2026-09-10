"""
Custom exception hierarchy for Stealthix.

This module provides a structured exception hierarchy to replace broad
exception handling throughout the codebase, enabling better error
classification, logging, and debugging.
"""

from __future__ import annotations


class StealthixError(Exception):
    """Base exception for all Stealthix errors."""

    pass


class ScanError(StealthixError):
    """Errors during scan execution."""

    pass


class DetectionError(ScanError):
    """Errors during vulnerability detection."""

    pass


class AuthError(ScanError):
    """Errors during authentication."""

    pass


class ExtractionError(ScanError):
    """Errors during data extraction."""

    pass


class EvasionError(ScanError):
    """Errors during WAF evasion."""

    pass


class NetworkError(ScanError):
    """Network-related errors (timeouts, connection failures)."""

    pass


class ConfigError(StealthixError):
    """Configuration validation errors."""

    pass


class CredentialError(StealthixError):
    """Credential storage/retrieval errors."""

    pass


class PluginError(StealthixError):
    """Plugin-related errors (loading, execution)."""

    pass


class ReconError(ScanError):
    """Reconnaissance-related errors."""

    pass
