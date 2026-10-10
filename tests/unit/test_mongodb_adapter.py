from __future__ import annotations

import pytest

from stealthix.direct import (
    DirectTarget,
    MongoDBDirectAdapter,
    adapter_for_backend,
    require_adapter,
)


def test_mongodb_adapter_registration() -> None:
    adapter = adapter_for_backend("mongodb")
    assert isinstance(adapter, MongoDBDirectAdapter)
    assert adapter_for_backend("mongo") is adapter
    assert adapter_for_backend("mongod") is adapter
    assert require_adapter("mongodb") is adapter
    caps = adapter.capabilities
    assert caps.backend == "mongodb"
    assert caps.family == "nosql"
    assert "http" in caps.transports
    assert "mongodb" in caps.transports
    assert set(caps.operations) == {"databases", "tables", "columns", "dump"}


def test_mongodb_http_requests() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="http://localhost:28017", database="shop")

    # databases
    req_db = adapter.build_request(target, "databases")
    assert req_db.transport == "http"
    assert req_db.method == "GET"
    assert req_db.path == "/_status"
    assert req_db.params.get("listDatabases") == "1"

    # tables (collections)
    req_tables = adapter.build_request(target, "tables")
    assert req_tables.transport == "http"
    assert req_tables.method == "GET"
    assert req_tables.path == "/shop/_collections"
    assert req_tables.database == "shop"

    # dump
    req_dump = adapter.build_request(target, "dump", table="orders", limit=10)
    assert req_dump.transport == "http"
    assert req_dump.method == "GET"
    assert req_dump.path == "/shop/orders"
    assert req_dump.params.get("limit") == "10"

    # columns (with projection)
    req_cols = adapter.build_request(target, "columns", table="orders", columns=["user", "total"])
    assert req_cols.transport == "http"
    assert req_cols.method == "POST"
    assert req_cols.path == "/shop/orders"
    assert req_cols.body.get("projection") == {"user": 1, "total": 1}


def test_mongodb_wire_requests() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="mongodb://localhost:27017", database="analytics")

    # databases
    req_db = adapter.build_request(target, "databases")
    assert req_db.transport == "mongodb"
    assert req_db.action == "listDatabases"
    assert req_db.database == "admin"
    assert req_db.body.get("listDatabases") == 1

    # tables
    req_tables = adapter.build_request(target, "tables")
    assert req_tables.transport == "mongodb"
    assert req_tables.action == "listCollections"
    assert req_tables.database == "analytics"

    # dump
    req_dump = adapter.build_request(target, "dump", table="events", limit=50)
    assert req_dump.transport == "mongodb"
    assert req_dump.action == "find"
    assert req_dump.table == "events"
    assert req_dump.body.get("limit") == 50


def test_mongodb_parse_response_databases() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="http://localhost:28017")
    req = adapter.build_request(target, "databases")

    # Wire command format
    raw_wire = {"databases": [{"name": "admin"}, {"name": "config"}, {"name": "app"}], "ok": 1.0}
    parsed = adapter.parse_response("databases", raw_wire, req)
    assert parsed == {"databases": ["admin", "config", "app"]}

    # Simple list format
    raw_list = ["db1", "db2"]
    parsed_list = adapter.parse_response("databases", raw_list, req)
    assert parsed_list == {"databases": ["db1", "db2"]}


def test_mongodb_parse_response_tables() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="http://localhost:28017", database="app")
    req = adapter.build_request(target, "tables")

    # Cursor format
    raw_cursor = {"cursor": {"firstBatch": [{"name": "users"}, {"name": "sessions"}]}}
    parsed = adapter.parse_response("tables", raw_cursor, req)
    assert parsed == {"tables": ["users", "sessions"]}

    # Collections list format
    raw_colls = {"collections": [{"name": "items"}]}
    parsed_colls = adapter.parse_response("tables", raw_colls, req)
    assert parsed_colls == {"tables": ["items"]}


def test_mongodb_parse_response_dump_and_columns() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="http://localhost:28017", database="app", table="users")
    req = adapter.build_request(target, "dump")

    raw_docs = [
        {"_id": "1", "name": "Alice", "profile": {"age": 30, "city": "NYC"}},
        {"_id": "2", "name": "Bob", "email": "bob@example.com"},
    ]

    dump_parsed = adapter.parse_response("dump", raw_docs, req)
    assert dump_parsed == {"rows": raw_docs}

    cols_parsed = adapter.parse_response("columns", raw_docs, req)
    assert set(cols_parsed["columns"]) == {"_id", "name", "profile", "profile.age", "profile.city", "email"}


def test_mongodb_probe() -> None:
    adapter = MongoDBDirectAdapter()
    target = DirectTarget(service="mongodb", endpoint="http://localhost:28017", database="shop", table="products")

    # Probe without executor
    res_no_exec = adapter.probe(target, "databases")
    assert not res_no_exec.success
    assert any("No executor" in w for w in res_no_exec.warnings)

    # Probe with simulated response
    mock_raw = {"databases": [{"name": "shop"}, {"name": "test"}]}
    res_mock = adapter.probe(target, "databases", response=mock_raw)
    assert res_mock.success
    assert res_mock.parsed == {"databases": ["shop", "test"]}
    assert res_mock.elapsed_ms is not None
