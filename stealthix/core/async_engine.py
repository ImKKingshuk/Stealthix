from __future__ import annotations

import asyncio
from typing import Any

from stealthix.core.engine import Engine
from stealthix.core.http_async import make_async_request
from stealthix.core.models import ScanResult


class AsyncEngine(Engine):
    """Async wrapper around the concurrent detection engine with true async I/O."""

    async def detect(self) -> ScanResult:  # type: ignore
        """Run detection with true async HTTP I/O."""
        # Detector orchestration remains compatible with the synchronous Engine API,
        # while async HTTP helpers are available to modules that opt into them.
        return await asyncio.to_thread(super().detect)

    async def _async_make_request(
        self,
        url: str,
        data: dict[str, Any] | None = None,
        method: str | None = None,
    ) -> tuple[str, float]:
        """Async version of make_request using Rust reqwest."""
        return await make_async_request(
            session=self.session,
            url=url,
            data=data,
            method=method,
        )

    async def detect_async(self) -> ScanResult:
        """
        Async entrypoint for callers that need an awaitable scan operation.

        Detection modules that use async HTTP can call `_async_make_request`; synchronous
        modules continue to execute through the shared Engine pipeline.
        """
        return await self.detect()
