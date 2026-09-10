from __future__ import annotations

from stealthix.direct.adapters import (
    CassandraDirectAdapter,
    CosmosDBDirectAdapter,
    CouchDBDirectAdapter,
    DynamoDBDirectAdapter,
    Neo4jDirectAdapter,
    RedisDirectAdapter,
    SearchDirectAdapter,
)
from stealthix.direct.base import (
    DirectAdapterCapabilities,
    DirectExecutor,
    DirectProbeResult,
    DirectServiceAdapter,
    DirectServiceAdapterBase,
    DirectServiceRequest,
    DirectTarget,
)
from stealthix.direct.registry import (
    adapter_for_backend,
    adapter_for_target,
    available_adapters,
    capabilities_for_backend,
    capability_matrix,
    require_adapter,
)

__all__ = [
    "CassandraDirectAdapter",
    "CosmosDBDirectAdapter",
    "CouchDBDirectAdapter",
    "DirectAdapterCapabilities",
    "DirectExecutor",
    "DirectProbeResult",
    "DirectServiceAdapter",
    "DirectServiceAdapterBase",
    "DirectServiceRequest",
    "DirectTarget",
    "DynamoDBDirectAdapter",
    "Neo4jDirectAdapter",
    "RedisDirectAdapter",
    "SearchDirectAdapter",
    "adapter_for_backend",
    "adapter_for_target",
    "available_adapters",
    "capabilities_for_backend",
    "capability_matrix",
    "require_adapter",
]
