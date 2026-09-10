from __future__ import annotations

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.extraction.nosql_adapters import adapter_for_backend
from stealthix.extraction.nosql_extract import (
    dump_table_nosql,
    enumerate_columns_nosql,
    enumerate_databases_nosql,
)


def test_adapter_selection_exposes_backend_capabilities() -> None:
    cases = {
        "mongodb": "mongodb",
        "couchdb": "couchdb",
        "redis": "redis",
        "elasticsearch": "search",
        "opensearch": "search",
        "neo4j": "neo4j",
        "cassandra": "cassandra",
        "dynamodb": "dynamodb-cosmosdb",
        "cosmosdb": "dynamodb-cosmosdb",
        "ycql": "yugabyte-ycql",
        "unknown": "generic",
    }

    for backend, expected in cases.items():
        adapter = adapter_for_backend(backend)

        assert adapter.capabilities.backend == expected
        assert set(adapter.capabilities.operations) == {"databases", "tables", "columns", "dump"}


def test_couchdb_adapter_preserves_database_result_shape(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com/app", dbms="couchdb"))

    monkeypatch.setattr(
        "stealthix.extraction.nosql_extract._make_request",
        lambda _session, url, data=None, method=None: ('["users","audit"]', 0.02),
    )

    result = enumerate_databases_nosql(session)

    assert result["success"] is True
    assert sorted(result["databases"]) == ["audit", "users"]
    assert result["adapter"] == "couchdb"
    assert result["capabilities"]["direct_http"] is True
    assert {"operation", "dbms", "payloads", "responses", "warnings", "count"} <= set(result)


def test_redis_adapter_preserves_dump_result_shape(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com/app?id=1", dbms="redis"))

    def fake_injected(_session, payload):
        if payload.startswith("HGETALL"):
            return "http://example.com/app?id=1", "name\nalice\nrole\nadmin", 0.01
        return "http://example.com/app?id=1", "", 0.01

    monkeypatch.setattr("stealthix.extraction.nosql_extract._request_injected", fake_injected)

    result = dump_table_nosql(session, table="user:1", columns=["name", "role"])

    assert result["success"] is True
    assert result["rows"] == [{"name": "alice", "role": "admin"}]
    assert result["adapter"] == "redis"
    assert {"table", "database", "columns", "rows"} <= set(result)


def test_search_adapter_extracts_mapping_columns(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://search.example/app", dbms="opensearch"))

    monkeypatch.setattr(
        "stealthix.extraction.nosql_extract._make_request",
        lambda _session, url, data=None, method=None: (
            '{"users":{"mappings":{"properties":{"name":{"type":"text"},"email":{"type":"keyword"}}}}}',
            0.02,
        ),
    )

    result = enumerate_columns_nosql(session, table="users")

    assert result["success"] is True
    assert {"email", "name"} <= set(result["columns"])
    assert result["adapter"] == "search"


def test_unknown_backend_uses_conservative_fallback(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com/app?id=1", dbms="mysterydb"))

    monkeypatch.setattr(
        "stealthix.extraction.nosql_extract._request_injected",
        lambda _session, payload: ("http://example.com/app?id=1", "database: appdb", 0.01),
    )

    result = enumerate_databases_nosql(session)

    assert result["success"] is True
    assert result["databases"] == ["appdb"]
    assert result["adapter"] == "generic"
    assert result["capabilities"]["fallback"] is True
