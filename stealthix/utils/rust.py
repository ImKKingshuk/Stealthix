from __future__ import annotations

from importlib import import_module
from typing import Any


def _import_native_module() -> Any | None:
    try:
        return import_module("stealthix.stealthix_core")
    except Exception:
        return None


def load_rust_core() -> dict[str, Any]:
    stealthix_core = _import_native_module()
    if stealthix_core is None:
        return {}
    tamper_module = getattr(stealthix_core, "tamper", None)
    return {
        "HttpClient": getattr(stealthix_core, "HttpClient", None),
        "PoolConfig": getattr(stealthix_core, "PoolConfig", None),
        "AdaptivePoolConfig": getattr(stealthix_core, "AdaptivePoolConfig", None),
        "AdaptivePoolState": getattr(stealthix_core, "AdaptivePoolState", None),
        "ResponseMetrics": getattr(stealthix_core, "ResponseMetrics", None),
        "PayloadEncoder": getattr(stealthix_core, "PayloadEncoder", None),
        "PayloadObfuscator": getattr(stealthix_core, "PayloadObfuscator", None),
        "Fingerprint": getattr(stealthix_core, "Fingerprint", None),
        "TimingAnalyzer": getattr(stealthix_core, "TimingAnalyzer", None),
        "ErrorMatcher": getattr(stealthix_core, "ErrorMatcher", None),
        "DiffAnalyzer": getattr(stealthix_core, "DiffAnalyzer", None),
        "WafDetector": getattr(stealthix_core, "WafDetector", None),
        "Executor": getattr(stealthix_core, "Executor", None),
        "RateLimiter": getattr(stealthix_core, "RateLimiter", None),
        "CloudflareBypass": getattr(stealthix_core, "CloudflareBypass", None),
        "ModSecurityBypass": getattr(stealthix_core, "ModSecurityBypass", None),
        "DnsExfil": getattr(stealthix_core, "DnsExfil", None),
        "Extractor": getattr(stealthix_core, "Extractor", None),
        "tamper": tamper_module,
        "apply_tamper": getattr(tamper_module, "apply_tamper", None)
        if tamper_module is not None
        else None,
        "apply_tamper_sequence": getattr(tamper_module, "apply_tamper_sequence", None)
        if tamper_module is not None
        else None,
        "list_tamper_scripts": getattr(tamper_module, "list_tamper_scripts", None)
        if tamper_module is not None
        else None,
        "run_tui": getattr(stealthix_core, "run_tui", None),
    }
