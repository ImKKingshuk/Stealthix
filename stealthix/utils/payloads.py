from __future__ import annotations

import os
from collections.abc import Iterable
from functools import lru_cache
from pathlib import Path

from stealthix.payloads.generator import DEFAULT_EXPANDED_LIMITS, build_payload_catalog
from stealthix.payloads.nosql_advanced import get_advanced_payloads

_RISK_BUDGETS: dict[str, dict[int, int]] = {
    "sqli": {1: 24, 2: 96, 3: 320},
    "error_based": {1: 10, 2: 32, 3: 120},
    "union_based": {1: 8, 2: 24, 3: 72},
    "time_based": {1: 6, 2: 20, 3: 64},
    "stacked": {1: 6, 2: 18, 3: 48},
    "nosqli": {1: 18, 2: 64, 3: 220},
    "newsql": {1: 10, 2: 30, 3: 96},
}

# Cache configuration
_CACHE_SIZE = int(os.environ.get("STEALTHIX_PAYLOAD_CACHE_SIZE", "128"))
_DISABLE_CACHE = os.environ.get("STEALTHIX_DISABLE_PAYLOAD_CACHE", "0").strip().lower() in {
    "1",
    "true",
    "yes",
    "on",
}


def _dedupe(lines: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for line in lines:
        value = str(line or "").strip()
        if not value or value.startswith("#") or value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


def _read_payload_file(kind: str) -> list[str]:
    base = Path(__file__).resolve().parent.parent / "payloads"
    file_path = base / f"{kind}.txt"
    if not file_path.exists():
        return []
    lines = file_path.read_text(encoding="utf-8").splitlines()
    return _dedupe(lines)


def load_base_payloads(kind: str) -> list[str]:
    """Load unexpanded payload lines from stealthix/payloads/<kind>.txt."""
    return _read_payload_file(kind)


def load_payloads(kind: str) -> list[str]:
    """Backward-compatible alias for raw payload catalogs."""
    return load_base_payloads(kind)


def payload_budget_for_risk(kind: str, risk: int, total_available: int) -> int:
    family = str(kind or "").strip().lower()
    budgets = _RISK_BUDGETS.get(family, {})
    return max(1, min(int(total_available), budgets.get(int(risk or 1), int(total_available))))


def _seed_payloads(
    kind: str,
    *,
    custom_payloads: Iterable[str] | None = None,
    include_advanced: bool = True,
    advanced_backend: str | None = None,
) -> list[str]:
    family = str(kind or "").strip().lower()
    if custom_payloads is not None:
        return _dedupe(list(custom_payloads))
    payloads = list(load_base_payloads(family))
    if include_advanced and family == "nosqli":
        payloads.extend(get_advanced_payloads(advanced_backend or "mongodb"))
    return _dedupe(payloads)


@lru_cache(maxsize=_CACHE_SIZE)
def expand_payloads(
    kind: str,
    payloads: tuple[str, ...],
    *,
    max_payloads: int | None = None,
    include_advanced: bool = True,
) -> tuple[str, ...]:
    family = str(kind or "").strip().lower()
    combined = list(payloads)
    if include_advanced and family == "nosqli":
        combined.extend(get_advanced_payloads("mongodb"))
    combined = _dedupe(combined)
    if not combined:
        return ()
    if _DISABLE_CACHE or os.environ.get(
        "STEALTHIX_DISABLE_PAYLOAD_MUTATION", "0"
    ).strip().lower() in {"1", "true", "yes", "on"}:
        if max_payloads is None:
            return tuple(combined)
        return tuple(combined[: max(1, int(max_payloads))])
    limit = (
        max_payloads
        if max_payloads is not None
        else DEFAULT_EXPANDED_LIMITS.get(family, len(combined))
    )
    result = build_payload_catalog(family, combined, max_payloads=limit)
    return tuple(result)


def resolve_payloads(
    kind: str,
    *,
    custom_payloads: list[str] | None = None,
    expand: bool = False,
    max_payloads: int | None = None,
    include_advanced: bool = True,
    risk: int | None = None,
    advanced_backend: str | None = None,
) -> list[str]:
    family = str(kind or "").strip().lower()
    base = _seed_payloads(
        family,
        custom_payloads=custom_payloads,
        include_advanced=include_advanced,
        advanced_backend=advanced_backend,
    )
    if max_payloads is None and risk is not None:
        available = DEFAULT_EXPANDED_LIMITS.get(family, len(base)) if expand else len(base)
        max_payloads = payload_budget_for_risk(family, risk, available)
    if not expand:
        if max_payloads is None:
            return base
        return base[: max(1, int(max_payloads))]
    # Convert list to tuple for caching
    expanded = expand_payloads(
        kind, tuple(base), max_payloads=max_payloads, include_advanced=include_advanced
    )
    return list(expanded)


def clear_payload_cache() -> None:
    """Clear the payload expansion cache."""
    expand_payloads.cache_clear()


def get_cache_stats() -> dict[str, int]:
    """Get cache statistics.

    Returns:
        Dictionary with cache stats
    """
    cache_info = expand_payloads.cache_info()
    return {
        "hits": cache_info.hits or 0,
        "misses": cache_info.misses or 0,
        "maxsize": cache_info.maxsize or 0,
        "currsize": cache_info.currsize or 0,
    }


__all__ = [
    "expand_payloads",
    "load_base_payloads",
    "load_payloads",
    "payload_budget_for_risk",
    "resolve_payloads",
    "clear_payload_cache",
    "get_cache_stats",
]
