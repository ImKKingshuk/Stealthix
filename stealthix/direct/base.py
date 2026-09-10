from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol, runtime_checkable


@dataclass(frozen=True)
class DirectTarget:
    """Direct NoSQL/NewSQL service target metadata.

    The direct layer deliberately stores connection details without creating a
    client. Production callers can pass a live executor, while tests can pass a
    fake callable that receives the built request.
    """

    service: str
    endpoint: str | None = None
    database: str | None = None
    table: str | None = None
    namespace: str | None = None
    region: str | None = None
    options: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "service", self.service.strip().lower())
        object.__setattr__(self, "options", dict(self.options))


@dataclass(frozen=True)
class DirectServiceRequest:
    operation: str
    transport: str
    action: str
    method: str | None = None
    path: str | None = None
    url: str | None = None
    command: tuple[str, ...] = ()
    query: str | None = None
    body: Mapping[str, Any] = field(default_factory=dict)
    params: Mapping[str, Any] = field(default_factory=dict)
    headers: Mapping[str, str] = field(default_factory=dict)
    database: str | None = None
    table: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", self.method.upper() if self.method else None)
        object.__setattr__(self, "command", tuple(str(part) for part in self.command))
        object.__setattr__(self, "body", dict(self.body))
        object.__setattr__(self, "params", dict(self.params))
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "metadata", dict(self.metadata))

    def as_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation,
            "transport": self.transport,
            "action": self.action,
            "method": self.method,
            "path": self.path,
            "url": self.url,
            "command": list(self.command),
            "query": self.query,
            "body": dict(self.body),
            "params": dict(self.params),
            "headers": dict(self.headers),
            "database": self.database,
            "table": self.table,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class DirectAdapterCapabilities:
    backend: str
    family: str
    aliases: tuple[str, ...]
    operations: tuple[str, ...]
    transports: tuple[str, ...]
    description: str = ""
    executor_optional: bool = True
    live_clients: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "family": self.family,
            "aliases": list(self.aliases),
            "operations": list(self.operations),
            "transports": list(self.transports),
            "description": self.description,
            "executor_optional": self.executor_optional,
            "live_clients": self.live_clients,
        }


@dataclass
class DirectProbeResult:
    target: DirectTarget
    adapter: str
    operation: str
    request: DirectServiceRequest
    raw: Any = None
    parsed: dict[str, Any] = field(default_factory=dict)
    success: bool = False
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    elapsed_ms: float | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "target": {
                "service": self.target.service,
                "endpoint": self.target.endpoint,
                "database": self.target.database,
                "table": self.target.table,
                "namespace": self.target.namespace,
                "region": self.target.region,
                "options": dict(self.target.options),
            },
            "adapter": self.adapter,
            "operation": self.operation,
            "request": self.request.as_dict(),
            "raw": self.raw,
            "parsed": dict(self.parsed),
            "success": self.success,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
            "elapsed_ms": self.elapsed_ms,
        }


DirectExecutor = Callable[[DirectTarget, DirectServiceRequest], Any]


@runtime_checkable
class DirectServiceAdapter(Protocol):
    capabilities: DirectAdapterCapabilities

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest: ...

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]: ...

    def probe(
        self,
        target: DirectTarget,
        operation: str,
        *,
        executor: DirectExecutor | None = None,
        response: Any = None,
        **kwargs: Any,
    ) -> DirectProbeResult: ...


_NO_RESPONSE = object()


class DirectServiceAdapterBase:
    capabilities: ClassVar[DirectAdapterCapabilities] = DirectAdapterCapabilities(
        backend="generic",
        family="nosql",
        aliases=("generic", "auto", ""),
        operations=("databases", "tables", "columns", "dump"),
        transports=("injected",),
        description="Generic direct-service adapter base.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        raise NotImplementedError

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        return {"value": raw} if raw is not None else {}

    def probe(
        self,
        target: DirectTarget,
        operation: str,
        *,
        executor: DirectExecutor | None = None,
        response: Any = _NO_RESPONSE,
        **kwargs: Any,
    ) -> DirectProbeResult:
        request = self.build_request(target, operation, **kwargs)
        result = DirectProbeResult(
            target=target,
            adapter=self.capabilities.backend,
            operation=operation,
            request=request,
        )
        if response is _NO_RESPONSE and executor is None:
            result.warnings.append("No executor supplied; request was built but not executed.")
            return result

        started = time.perf_counter()
        try:
            if response is _NO_RESPONSE:
                if executor is None:
                    raise RuntimeError("No executor supplied.")
                raw = executor(target, request)
            else:
                raw = response
            result.raw = raw
            result.parsed = self.parse_response(operation, raw, request)
            result.success = not result.errors and bool(result.parsed)
        except Exception as exc:
            result.errors.append(str(exc))
            result.success = False
        finally:
            result.elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
        return result
