from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class RequestHistory:
    entries: list[dict[str, Any]] = field(default_factory=list)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def add(
        self,
        url: str,
        method: str,
        status: str | None,
        elapsed: float,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        with self._lock:
            self.entries.append(
                {
                    "url": url,
                    "method": method,
                    "status": status,
                    "elapsed": elapsed,
                    "metadata": metadata or {},
                    "timestamp": datetime.now(UTC).isoformat(),
                }
            )

    def to_list(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.entries)

    def __len__(self) -> int:
        with self._lock:
            return len(self.entries)

    def latest(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self.entries[-1]) if self.entries else None

    @staticmethod
    def from_list(items: list[dict[str, Any]]) -> RequestHistory:
        history = RequestHistory()
        with history._lock:
            history.entries = list(items)
        return history
