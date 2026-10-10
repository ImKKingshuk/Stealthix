from __future__ import annotations

from stealthix.direct.adapters import (
    CassandraDirectAdapter,
    CosmosDBDirectAdapter,
    CouchDBDirectAdapter,
    DynamoDBDirectAdapter,
    MongoDBDirectAdapter,
    Neo4jDirectAdapter,
    RedisDirectAdapter,
    SearchDirectAdapter,
)
from stealthix.direct.base import DirectAdapterCapabilities, DirectServiceAdapter, DirectTarget

_ADAPTERS: tuple[DirectServiceAdapter, ...] = (
    RedisDirectAdapter(),
    CouchDBDirectAdapter(),
    SearchDirectAdapter(),
    Neo4jDirectAdapter(),
    CassandraDirectAdapter(),
    DynamoDBDirectAdapter(),
    CosmosDBDirectAdapter(),
    MongoDBDirectAdapter(),
)


def available_adapters() -> tuple[DirectServiceAdapter, ...]:
    return _ADAPTERS


def capability_matrix() -> dict[str, dict[str, object]]:
    return {adapter.capabilities.backend: adapter.capabilities.as_dict() for adapter in _ADAPTERS}


def capabilities_for_backend(backend: str | None) -> DirectAdapterCapabilities | None:
    adapter = adapter_for_backend(backend)
    return adapter.capabilities if adapter is not None else None


def adapter_for_backend(backend: str | None) -> DirectServiceAdapter | None:
    normalized = str(backend or "").strip().lower()
    for adapter in _ADAPTERS:
        if normalized in adapter.capabilities.aliases or normalized == adapter.capabilities.backend:
            return adapter
    return None


def adapter_for_target(target: DirectTarget) -> DirectServiceAdapter | None:
    return adapter_for_backend(target.service)


def require_adapter(backend: str | None) -> DirectServiceAdapter:
    adapter = adapter_for_backend(backend)
    if adapter is None:
        raise ValueError(
            f"No direct-service adapter registered for backend: {backend or 'unknown'}"
        )
    return adapter


__all__ = [
    "adapter_for_backend",
    "adapter_for_target",
    "available_adapters",
    "capabilities_for_backend",
    "capability_matrix",
    "require_adapter",
]
