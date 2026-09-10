from __future__ import annotations

from typing import Any

import pytest

from stealthix.direct import (
    DirectServiceRequest,
    DirectTarget,
    adapter_for_backend,
    capabilities_for_backend,
    capability_matrix,
    require_adapter,
)


def test_direct_adapter_selection_and_capability_metadata() -> None:
    cases = {
        "redis": "redis",
        "couchdb": "couchdb",
        "elasticsearch": "search",
        "opensearch": "search",
        "neo4j": "neo4j",
        "cassandra": "cassandra",
        "scylla": "cassandra",
        "dynamodb": "dynamodb",
        "cosmosdb": "cosmosdb",
    }

    for alias, backend in cases.items():
        adapter = require_adapter(alias)
        capabilities = capabilities_for_backend(alias)

        assert adapter.capabilities.backend == backend
        assert capabilities is not None
        assert set(capabilities.operations) == {"databases", "tables", "columns", "dump"}
        assert capabilities.executor_optional is True
        assert capabilities.live_clients is False

    matrix = capability_matrix()
    assert {"redis", "couchdb", "search", "neo4j", "cassandra", "dynamodb", "cosmosdb"} <= set(
        matrix
    )
    assert adapter_for_backend("unknown") is None


def test_probe_without_executor_returns_built_request_only() -> None:
    adapter = require_adapter("redis")
    result = adapter.probe(DirectTarget(service="redis"), "tables")

    assert result.success is False
    assert result.request.command == ("SCAN", "0", "MATCH", "*", "COUNT", "100")
    assert result.warnings == ["No executor supplied; request was built but not executed."]


def test_redis_builds_commands_and_parses_fake_executor() -> None:
    adapter = require_adapter("redis")
    calls: list[DirectServiceRequest] = []

    def fake_executor(_target: DirectTarget, request: DirectServiceRequest) -> Any:
        calls.append(request)
        assert request.transport == "redis-command"
        if request.command[0] == "INFO":
            return "# Keyspace\r\ndb0:keys=2,expires=0\r\ndb2:keys=1,expires=0"
        if request.command[0] == "HGETALL":
            return ["name", "alice", "role", "admin"]
        raise AssertionError(request.command)

    dbs = adapter.probe(DirectTarget(service="redis"), "databases", executor=fake_executor)
    row = adapter.probe(
        DirectTarget(service="redis", table="user:1"), "dump", executor=fake_executor
    )

    assert dbs.parsed["databases"] == ["db0", "db2"]
    assert row.request.command == ("HGETALL", "user:1")
    assert row.parsed["rows"] == [{"name": "alice", "role": "admin"}]
    assert len(calls) == 2


def test_couchdb_builds_urls_and_parses_documents() -> None:
    adapter = require_adapter("couchdb")
    target = DirectTarget(service="couchdb", endpoint="http://db.local", database="app")

    db_request = adapter.build_request(target, "databases")
    columns = adapter.probe(
        target,
        "columns",
        response={
            "rows": [
                {"id": "u1", "doc": {"_id": "u1", "name": "alice", "profile": {"email": "a@x"}}},
                {"id": "u2", "doc": {"_id": "u2", "role": "admin"}},
            ]
        },
    )

    assert db_request.method == "GET"
    assert db_request.url == "http://db.local/_all_dbs"
    assert columns.request.path == "/app/_all_docs?include_docs=true&limit=100"
    assert columns.parsed["columns"] == ["name", "profile", "profile.email", "role"]


def test_search_adapter_builds_opensearch_shapes_and_parses_hits() -> None:
    adapter = require_adapter("opensearch")
    target = DirectTarget(service="opensearch", endpoint="http://search.local", table="users")

    dump_request = adapter.build_request(target, "dump", columns=["name", "email"], limit=5)
    mapping = adapter.probe(
        target,
        "columns",
        response={
            "users": {
                "mappings": {
                    "properties": {
                        "name": {"type": "text"},
                        "profile": {"properties": {"age": {"type": "integer"}}},
                    }
                }
            }
        },
    )
    dump = adapter.probe(
        target,
        "dump",
        response={"hits": {"hits": [{"_source": {"name": "alice", "email": "a@x"}}]}},
    )

    assert dump_request.method == "POST"
    assert dump_request.path == "/users/_search"
    assert dump_request.body == {
        "query": {"match_all": {}},
        "size": 5,
        "_source": ["name", "email"],
    }
    assert mapping.parsed["columns"] == ["name", "profile", "profile.age"]
    assert dump.parsed["rows"] == [{"name": "alice", "email": "a@x"}]


def test_neo4j_builds_cypher_and_parses_record_shapes() -> None:
    adapter = require_adapter("neo4j")
    target = DirectTarget(service="neo4j", table="User")

    request = adapter.build_request(target, "columns")
    result = adapter.probe(
        target,
        "tables",
        response={
            "results": [{"columns": ["label"], "data": [{"row": ["User"]}, {"row": ["Org"]}]}]
        },
    )
    dump = adapter.probe(target, "dump", response=[{"n": {"name": "alice", "role": "admin"}}])

    assert request.query is not None
    assert "MATCH (n:`User`)" in request.query
    assert result.parsed["tables"] == ["Org", "User"]
    assert dump.parsed["rows"] == [{"name": "alice", "role": "admin"}]


def test_cassandra_builds_cql_and_parses_rows() -> None:
    adapter = require_adapter("cassandra")
    target = DirectTarget(service="cassandra", database="app", table="users")

    tables = adapter.build_request(target, "tables")
    columns = adapter.probe(
        target,
        "columns",
        response=[{"column_name": "id"}, {"column_name": "email"}],
    )
    dump = adapter.build_request(target, "dump", limit=10)

    assert tables.query == "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?"
    assert tables.params == {"keyspace_name": "app"}
    assert columns.parsed["columns"] == ["email", "id"]
    assert dump.query == "SELECT * FROM app.users LIMIT 10"


def test_dynamodb_builds_api_payloads_and_decodes_items() -> None:
    adapter = require_adapter("dynamodb")
    target = DirectTarget(service="dynamodb", table="Users", region="us-east-1")

    request = adapter.build_request(target, "dump", columns=["name", "age"], limit=3)
    result = adapter.probe(
        target,
        "dump",
        response={
            "Items": [
                {"name": {"S": "alice"}, "age": {"N": "42"}, "active": {"BOOL": True}},
            ]
        },
    )

    assert request.transport == "aws-api"
    assert request.action == "Scan"
    assert request.body["ProjectionExpression"] == "#n0, #n1"
    assert request.body["ExpressionAttributeNames"] == {"#n0": "name", "#n1": "age"}
    assert result.parsed["rows"] == [{"name": "alice", "age": 42, "active": True}]


def test_cosmosdb_builds_rest_query_and_parses_resources() -> None:
    adapter = require_adapter("cosmosdb")
    target = DirectTarget(
        service="cosmosdb",
        endpoint="https://acct.documents.azure.com",
        database="app",
        table="users",
    )

    request = adapter.build_request(target, "dump", columns=["name"], limit=2)
    tables = adapter.probe(
        target,
        "tables",
        response={"DocumentCollections": [{"id": "users"}, {"id": "audit"}]},
    )
    columns = adapter.probe(
        target,
        "columns",
        response={"Documents": [{"id": "u1", "name": "alice", "profile": {"email": "a@x"}}]},
    )

    assert request.method == "POST"
    assert request.path == "/dbs/app/colls/users/docs"
    assert request.body == {"query": "SELECT TOP 2 c.name FROM c", "parameters": []}
    assert request.headers["x-ms-documentdb-isquery"] == "true"
    assert tables.parsed["tables"] == ["users", "audit"]
    assert columns.parsed["columns"] == ["id", "name", "profile", "profile.email"]


def test_require_adapter_rejects_unknown_backend() -> None:
    with pytest.raises(ValueError, match="No direct-service adapter"):
        require_adapter("not-a-service")
