from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field


@dataclass
class ScanControl:
    pause: threading.Event = field(default_factory=threading.Event)
    cancel: threading.Event = field(default_factory=threading.Event)
    _paused_started_at: float | None = None
    _paused_total: float = 0.0

    def __post_init__(self) -> None:
        self.pause.set()

    def set_paused(self, paused: bool) -> None:
        if paused:
            if self.pause.is_set():
                self.pause.clear()
                self._paused_started_at = time.monotonic()
        else:
            if not self.pause.is_set():
                self.pause.set()
                if self._paused_started_at is not None:
                    self._paused_total += max(0.0, time.monotonic() - self._paused_started_at)
                self._paused_started_at = None

    def request_cancel(self) -> None:
        self.cancel.set()
        self.pause.set()

    def wait_if_paused(self) -> None:
        while not self.pause.is_set():
            if self.cancel.is_set():
                raise RuntimeError("scan cancelled")
            time.sleep(0.05)
        if self.cancel.is_set():
            raise RuntimeError("scan cancelled")

    async def async_wait_if_paused(self) -> None:
        import asyncio

        while not self.pause.is_set():
            if self.cancel.is_set():
                raise RuntimeError("scan cancelled")
            await asyncio.sleep(0.05)
        if self.cancel.is_set():
            raise RuntimeError("scan cancelled")

    def active_elapsed(self, started_at: float) -> float:
        paused_total = self._paused_total
        if self._paused_started_at is not None:
            paused_total += max(0.0, time.monotonic() - self._paused_started_at)
        return max(0.0, time.monotonic() - started_at - paused_total)
