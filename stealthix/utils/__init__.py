from __future__ import annotations

__all__ = [
    "RequestCache",
    "apply_waf_bypass",
    "expand_payloads",
    "get_cache",
    "load_base_payloads",
    "load_payloads",
    "load_rust_core",
    "payload_budget_for_risk",
    "resolve_payloads",
]

from typing import TYPE_CHECKING

from stealthix.utils.cache import RequestCache, get_cache
from stealthix.utils.payloads import (
    expand_payloads,
    load_base_payloads,
    load_payloads,
    payload_budget_for_risk,
    resolve_payloads,
)
from stealthix.utils.rust import load_rust_core

if TYPE_CHECKING:
    from stealthix.core.session import ScanSession


def apply_waf_bypass(session: ScanSession, payload: str) -> str:
    from stealthix.utils.bypass import apply_waf_bypass as _apply_waf_bypass

    return _apply_waf_bypass(session, payload)
