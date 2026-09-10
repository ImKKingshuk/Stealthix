from __future__ import annotations

import os
import re
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

_TOKEN_RE = re.compile(r"stealthix[0-9a-f]{6,}", re.IGNORECASE)


def _truthy(value: str | None, default: bool = True) -> bool:
    if value is None:
        return default
    return value.strip().lower() not in {"0", "false", "no", "off"}


def cache_enabled() -> bool:
    return _truthy(os.environ.get("STEALTHIX_CACHE"), default=True)


def cache_ttl() -> float:
    try:
        return float(os.environ.get("STEALTHIX_CACHE_TTL", "30"))
    except Exception:
        return 30.0


def cache_max_items() -> int:
    try:
        return int(os.environ.get("STEALTHIX_CACHE_MAX", "512"))
    except Exception:
        return 512


def is_cacheable(url: str, body: str) -> bool:
    if _TOKEN_RE.search(url) or _TOKEN_RE.search(body):
        return False
    return True


@dataclass
class CacheEntry:
    value: Any
    created_at: float


class RequestCache:
    def __init__(self, max_items: int, ttl_seconds: float) -> None:
        self._max_items = max(1, int(max_items))
        self._ttl = max(0.0, float(ttl_seconds))
        self._store: OrderedDict[tuple[Any, ...], CacheEntry] = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: tuple[Any, ...]) -> Any | None:
        with self._lock:
            now = time.monotonic()
            entry = self._store.get(key)
            if not entry:
                return None
            if self._ttl and now - entry.created_at > self._ttl:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return entry.value

    def set(self, key: tuple[Any, ...], value: Any) -> None:
        with self._lock:
            now = time.monotonic()
            self._store[key] = CacheEntry(value=value, created_at=now)
            self._store.move_to_end(key)
            while len(self._store) > self._max_items:
                self._store.popitem(last=False)


_GLOBAL: RequestCache | None = None


def get_cache() -> RequestCache:
    global _GLOBAL
    if _GLOBAL is None:
        _GLOBAL = RequestCache(max_items=cache_max_items(), ttl_seconds=cache_ttl())
    return _GLOBAL
