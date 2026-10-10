from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Any
from urllib.parse import quote

from stealthix.direct.base import (
    DirectAdapterCapabilities,
    DirectServiceAdapterBase,
    DirectServiceRequest,
    DirectTarget,
)

_OPERATIONS = ("databases", "tables", "columns", "dump")
_SIMPLE_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _json(raw: Any) -> Any:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return raw
        if stripped[0] in "[{":
            try:
                return json.loads(stripped)
            except json.JSONDecodeError:
                return raw
    return raw


def _strings(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        return [item.strip() for item in re.split(r"[\r\n,]+", value) if item.strip()]
    if isinstance(value, Mapping):
        return [str(item) for item in value.keys()]
    if isinstance(value, Iterable):
        return [str(item) for item in value if item is not None and str(item).strip()]
    return [str(value)]


def _rows(raw: Any) -> list[dict[str, Any]]:
    data = _json(raw)
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, Mapping)]
    if not isinstance(data, Mapping):
        return []
    for key in ("rows", "items", "Items", "Documents", "records"):
        value = data.get(key)
        if isinstance(value, list):
            return [dict(item) for item in value if isinstance(item, Mapping)]
    return [dict(data)]


def _nested_keys(value: Any, *, skip_private: bool = True, prefix: str = "") -> set[str]:
    keys: set[str] = set()
    if isinstance(value, Mapping):
        for key, item in value.items():
            name = str(key)
            if skip_private and name.startswith("_"):
                continue
            full_name = f"{prefix}.{name}" if prefix else name
            keys.add(full_name)
            keys.update(_nested_keys(item, skip_private=skip_private, prefix=full_name))
    elif isinstance(value, list):
        for item in value:
            keys.update(_nested_keys(item, skip_private=skip_private, prefix=prefix))
    return keys


def _http_request(
    target: DirectTarget,
    *,
    operation: str,
    action: str,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
    params: Mapping[str, Any] | None = None,
    headers: Mapping[str, str] | None = None,
    metadata: Mapping[str, Any] | None = None,
    database: str | None = None,
    table: str | None = None,
) -> DirectServiceRequest:
    normalized_path = "/" + path.lstrip("/")
    endpoint = (target.endpoint or "").rstrip("/")
    url = f"{endpoint}{normalized_path}" if endpoint else None
    return DirectServiceRequest(
        operation=operation,
        transport="http",
        action=action,
        method=method,
        path=normalized_path,
        url=url,
        body=body or {},
        params=params or {},
        headers=headers or {},
        database=database or target.database,
        table=table or target.table,
        metadata=metadata or {},
    )


def _target_table(target: DirectTarget, table: str | None) -> str:
    value = table or target.table
    if not value:
        raise ValueError(
            "A table, collection, index, key, or label is required for this operation."
        )
    return value


def _cql_ident(value: str) -> str:
    if _SIMPLE_IDENT.fullmatch(value):
        return value
    return '"' + value.replace('"', '""') + '"'


def _cypher_label(value: str) -> str:
    return "`" + value.replace("`", "``") + "`"


def _dynamo_value(value: Any) -> Any:
    if not isinstance(value, Mapping) or len(value) != 1:
        if isinstance(value, Mapping):
            return {str(key): _dynamo_value(item) for key, item in value.items()}
        if isinstance(value, list):
            return [_dynamo_value(item) for item in value]
        return value
    kind, raw = next(iter(value.items()))
    if kind == "S":
        return raw
    if kind == "N":
        text = str(raw)
        try:
            return int(text) if re.fullmatch(r"-?\d+", text) else float(text)
        except ValueError:
            return raw
    if kind == "BOOL":
        return bool(raw)
    if kind == "NULL":
        return None
    if kind == "M" and isinstance(raw, Mapping):
        return {str(key): _dynamo_value(item) for key, item in raw.items()}
    if kind == "L" and isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, Mapping)):
        return [_dynamo_value(item) for item in raw]
    return raw


class RedisDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="redis",
        family="keyvalue",
        aliases=("redis",),
        operations=_OPERATIONS,
        transports=("redis-command",),
        description="Builds Redis commands and parses common redis-py/RESP-shaped responses.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        table = kwargs.get("table") or target.table
        if operation == "databases":
            command = ("INFO", "keyspace")
        elif operation == "tables":
            command = ("SCAN", "0", "MATCH", str(kwargs.get("pattern", "*")), "COUNT", "100")
        elif operation == "columns":
            command = ("HKEYS", _target_table(target, table))
        elif operation == "dump":
            command = ("HGETALL", _target_table(target, table))
        else:
            raise ValueError(f"Unsupported Redis direct operation: {operation}")
        return DirectServiceRequest(
            operation=operation,
            transport="redis-command",
            action=command[0],
            command=command,
            database=target.database,
            table=table,
        )

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if operation == "databases":
            if isinstance(data, Mapping):
                names = [str(key) for key in data.keys() if str(key).lower().startswith("db")]
            else:
                body = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                names = re.findall(r"\b(db\d+)\s*:", body, flags=re.IGNORECASE)
                if not names and "redis_version" in body.lower():
                    names = ["db0"]
            return {"databases": sorted(set(names))}
        if operation == "tables":
            if isinstance(data, (list, tuple)) and len(data) == 2 and isinstance(data[1], Iterable):
                return {"cursor": str(data[0]), "tables": _strings(data[1])}
            if isinstance(data, Mapping) and "keys" in data:
                return {"tables": _strings(data["keys"])}
            return {"tables": _strings(data)}
        if operation == "columns":
            return {"columns": _strings(data)}
        if operation == "dump":
            if isinstance(data, Mapping):
                return {"rows": [dict(data)]}
            parts = _strings(data)
            row = {parts[index]: parts[index + 1] for index in range(0, len(parts) - 1, 2)}
            return {"rows": [row] if row else []}
        return {}


class CouchDBDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="couchdb",
        family="document",
        aliases=("couchdb", "couch"),
        operations=_OPERATIONS,
        transports=("http",),
        description="Builds CouchDB REST API requests for database and document enumeration.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        database = kwargs.get("database") or target.database
        table = kwargs.get("table") or target.table
        if operation == "databases":
            return _http_request(
                target, operation=operation, action="_all_dbs", method="GET", path="/_all_dbs"
            )
        if not database:
            raise ValueError("CouchDB direct operations require a database except for databases.")
        db = quote(str(database), safe="")
        if operation == "tables":
            path = f"/{db}/_all_docs"
        elif operation in {"columns", "dump"}:
            path = f"/{db}/_all_docs?include_docs=true&limit={int(kwargs.get('limit', 100))}"
        else:
            raise ValueError(f"Unsupported CouchDB direct operation: {operation}")
        return _http_request(
            target,
            operation=operation,
            action="_all_docs",
            method="GET",
            path=path,
            metadata={"document": table} if table else {},
        )

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if operation == "databases":
            return {"databases": _strings(data)}
        if operation == "tables":
            rows = data.get("rows", []) if isinstance(data, Mapping) else []
            return {
                "tables": [
                    str(item["id"])
                    for item in rows
                    if isinstance(item, Mapping)
                    and item.get("id")
                    and not str(item["id"]).startswith("_")
                ]
            }
        docs = [
            dict(item["doc"])
            for item in (data.get("rows", []) if isinstance(data, Mapping) else [])
            if isinstance(item, Mapping) and isinstance(item.get("doc"), Mapping)
        ]
        if operation == "columns":
            return {
                "columns": sorted(set().union(*(_nested_keys(doc) for doc in docs))) if docs else []
            }
        if operation == "dump":
            return {"rows": docs}
        return {}


class SearchDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="search",
        family="search",
        aliases=("elasticsearch", "elastic", "opensearch", "search"),
        operations=_OPERATIONS,
        transports=("http",),
        description="Builds Elasticsearch/OpenSearch-compatible REST requests.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        index = kwargs.get("table") or kwargs.get("index") or target.table or target.database
        if operation in {"databases", "tables"}:
            return _http_request(
                target,
                operation=operation,
                action="_cat.indices",
                method="GET",
                path="/_cat/indices?format=json&h=index",
            )
        if operation == "columns":
            path = f"/{quote(str(index), safe='')}/_mapping" if index else "/_mapping"
            return _http_request(
                target, operation=operation, action="indices.get_mapping", method="GET", path=path
            )
        if operation == "dump":
            index_name = _target_table(target, str(index) if index else None)
            columns = list(kwargs.get("columns") or [])
            body: dict[str, Any] = {
                "query": {"match_all": {}},
                "size": int(kwargs.get("limit", 25)),
            }
            if columns:
                body["_source"] = columns
            return _http_request(
                target,
                operation=operation,
                action="search",
                method="POST",
                path=f"/{quote(index_name, safe='')}/_search",
                body=body,
            )
        raise ValueError(f"Unsupported search direct operation: {operation}")

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if operation in {"databases", "tables"}:
            if isinstance(data, list):
                names = [
                    str(item.get("index") or item.get("name"))
                    for item in data
                    if isinstance(item, Mapping) and (item.get("index") or item.get("name"))
                ]
            elif isinstance(data, Mapping):
                names = [str(key) for key in data.keys() if not str(key).startswith("_")]
            else:
                names = [
                    parts[2]
                    if len(parts := line.split()) > 2 and parts[0] in {"green", "yellow", "red"}
                    else parts[0]
                    for line in str(raw).splitlines()
                    if line.split() and line.split()[0] != "index"
                ]
            key = "databases" if operation == "databases" else "tables"
            return {key: sorted(set(name for name in names if name and not name.startswith(".")))}
        if operation == "columns":
            properties: dict[str, Any] = {}
            if isinstance(data, Mapping):
                for mapping in data.values():
                    if isinstance(mapping, Mapping):
                        props = mapping.get("mappings", {}).get("properties", {})
                        if isinstance(props, Mapping):
                            properties.update(props)
            return {"columns": sorted(_mapping_fields(properties))}
        if operation == "dump":
            hits = data.get("hits", {}).get("hits", []) if isinstance(data, Mapping) else []
            return {
                "rows": [
                    dict(hit.get("_source", {}))
                    for hit in hits
                    if isinstance(hit, Mapping) and isinstance(hit.get("_source"), Mapping)
                ]
            }
        return {}


def _mapping_fields(properties: Mapping[str, Any], prefix: str = "") -> set[str]:
    fields: set[str] = set()
    for key, value in properties.items():
        name = f"{prefix}.{key}" if prefix else str(key)
        fields.add(name)
        if isinstance(value, Mapping) and isinstance(value.get("properties"), Mapping):
            fields.update(_mapping_fields(value["properties"], name))
    return fields


class Neo4jDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="neo4j",
        family="graph",
        aliases=("neo4j", "cypher"),
        operations=_OPERATIONS,
        transports=("cypher",),
        description="Builds Cypher statements and parses common Neo4j record shapes.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        label = kwargs.get("table") or kwargs.get("label") or target.table
        limit = int(kwargs.get("limit", 25))
        if operation == "databases":
            query = "SHOW DATABASES"
        elif operation == "tables":
            query = "CALL db.labels() YIELD label RETURN label"
        elif operation == "columns":
            if label:
                query = (
                    f"MATCH (n:{_cypher_label(str(label))}) "
                    "UNWIND keys(n) AS property RETURN DISTINCT property LIMIT 100"
                )
            else:
                query = "CALL db.schema.nodeTypeProperties() YIELD propertyName RETURN DISTINCT propertyName"
        elif operation == "dump":
            label_query = f":{_cypher_label(str(label))}" if label else ""
            query = f"MATCH (n{label_query}) RETURN properties(n) AS n LIMIT {limit}"
        else:
            raise ValueError(f"Unsupported Neo4j direct operation: {operation}")
        return DirectServiceRequest(
            operation=operation,
            transport="cypher",
            action="run",
            query=query,
            database=kwargs.get("database") or target.database,
            table=label,
        )

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        records = _neo4j_records(_json(raw))
        if operation == "databases":
            return {
                "databases": sorted(
                    set(_pick(record, "name", "database", "databaseName") for record in records)
                    - {""}
                )
            }
        if operation == "tables":
            return {
                "tables": sorted(set(_pick(record, "label", "labels") for record in records) - {""})
            }
        if operation == "columns":
            return {
                "columns": sorted(
                    set(_pick(record, "property", "propertyName", "column") for record in records)
                    - {""}
                )
            }
        if operation == "dump":
            rows = []
            for record in records:
                value = record.get("n", record)
                if isinstance(value, Mapping):
                    rows.append(dict(value))
            return {"rows": rows}
        return {}


def _neo4j_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, Mapping)]
    if not isinstance(data, Mapping):
        return []
    if isinstance(data.get("records"), list):
        return [dict(item) for item in data["records"] if isinstance(item, Mapping)]
    rows: list[dict[str, Any]] = []
    for result in data.get("results", []) if isinstance(data.get("results"), list) else []:
        columns = result.get("columns", []) if isinstance(result, Mapping) else []
        for item in result.get("data", []) if isinstance(result, Mapping) else []:
            row = item.get("row", item) if isinstance(item, Mapping) else item
            if isinstance(row, list):
                rows.append(
                    {str(column): value for column, value in zip(columns, row, strict=False)}
                )
            elif isinstance(row, Mapping):
                rows.append(dict(row))
    return rows or [dict(data)]


def _pick(record: Mapping[str, Any], *keys: str) -> str:
    for key in keys:
        value = record.get(key)
        if isinstance(value, list):
            return str(value[0]) if value else ""
        if value is not None:
            return str(value)
    return ""


class CassandraDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="cassandra",
        family="wide-column",
        aliases=("cassandra", "scylla", "scylladb", "ycql", "yugabyte-ycql"),
        operations=_OPERATIONS,
        transports=("cql",),
        description="Builds CQL metadata and sampling queries.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        keyspace = kwargs.get("database") or target.database
        table = kwargs.get("table") or target.table
        if operation == "databases":
            query = "SELECT keyspace_name FROM system_schema.keyspaces"
            params: dict[str, Any] = {}
        elif operation == "tables":
            if not keyspace:
                raise ValueError("Cassandra table enumeration requires a keyspace.")
            query = "SELECT table_name FROM system_schema.tables WHERE keyspace_name = ?"
            params = {"keyspace_name": keyspace}
        elif operation == "columns":
            if not keyspace or not table:
                raise ValueError("Cassandra column enumeration requires keyspace and table.")
            query = (
                "SELECT column_name FROM system_schema.columns "
                "WHERE keyspace_name = ? AND table_name = ?"
            )
            params = {"keyspace_name": keyspace, "table_name": table}
        elif operation == "dump":
            if not table:
                raise ValueError("Cassandra dump requires a table.")
            qualified = (
                f"{_cql_ident(str(keyspace))}.{_cql_ident(str(table))}"
                if keyspace
                else _cql_ident(str(table))
            )
            query = f"SELECT * FROM {qualified} LIMIT {int(kwargs.get('limit', 25))}"
            params = {}
        else:
            raise ValueError(f"Unsupported Cassandra direct operation: {operation}")
        return DirectServiceRequest(
            operation=operation,
            transport="cql",
            action="execute",
            query=query,
            params=params,
            database=keyspace,
            table=table,
        )

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        rows = _rows(raw)
        if operation == "databases":
            return {
                "databases": sorted(
                    set(_pick(row, "keyspace_name", "keyspace") for row in rows) - {""}
                )
            }
        if operation == "tables":
            return {"tables": sorted(set(_pick(row, "table_name", "table") for row in rows) - {""})}
        if operation == "columns":
            return {
                "columns": sorted(set(_pick(row, "column_name", "column") for row in rows) - {""})
            }
        if operation == "dump":
            return {"rows": rows}
        return {}


class DynamoDBDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="dynamodb",
        family="multimodel",
        aliases=("dynamodb", "aws-dynamodb"),
        operations=_OPERATIONS,
        transports=("aws-api",),
        description="Builds DynamoDB API operation payloads and parses low-level item shapes.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        table = kwargs.get("table") or target.table
        body: dict[str, Any]
        if operation in {"databases", "tables"}:
            action = "ListTables"
            body = {}
        elif operation == "columns":
            action = "DescribeTable"
            body = {"TableName": _target_table(target, table)}
        elif operation == "dump":
            action = "Scan"
            columns = list(kwargs.get("columns") or [])
            body = {
                "TableName": _target_table(target, table),
                "Limit": int(kwargs.get("limit", 25)),
            }
            if columns:
                names = {f"#n{index}": column for index, column in enumerate(columns)}
                body["ProjectionExpression"] = ", ".join(names.keys())
                body["ExpressionAttributeNames"] = names
        else:
            raise ValueError(f"Unsupported DynamoDB direct operation: {operation}")
        return DirectServiceRequest(
            operation=operation,
            transport="aws-api",
            action=action,
            body=body,
            database=target.database,
            table=table,
            metadata={"region": target.region} if target.region else {},
        )

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if not isinstance(data, Mapping):
            return {}
        if operation in {"databases", "tables"}:
            key = "databases" if operation == "databases" else "tables"
            return {key: _strings(data.get("TableNames", []))}
        if operation == "columns":
            attrs = data.get("Table", {}).get("AttributeDefinitions", [])
            return {
                "columns": [
                    str(item["AttributeName"])
                    for item in attrs
                    if isinstance(item, Mapping) and item.get("AttributeName")
                ]
            }
        if operation == "dump":
            return {
                "rows": [
                    {str(key): _dynamo_value(value) for key, value in item.items()}
                    for item in data.get("Items", [])
                    if isinstance(item, Mapping)
                ]
            }
        return {}


class CosmosDBDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="cosmosdb",
        family="multimodel",
        aliases=("cosmosdb", "cosmos", "azure-cosmos-db", "azure-cosmos"),
        operations=_OPERATIONS,
        transports=("http",),
        description="Builds Azure Cosmos DB for NoSQL REST query shapes.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        database = kwargs.get("database") or target.database
        table = kwargs.get("table") or kwargs.get("container") or target.table
        if operation == "databases":
            return _http_request(
                target, operation=operation, action="list_databases", method="GET", path="/dbs"
            )
        if not database:
            raise ValueError("Cosmos DB direct operations require a database except for databases.")
        db = quote(str(database), safe="")
        if operation == "tables":
            return _http_request(
                target,
                operation=operation,
                action="list_containers",
                method="GET",
                path=f"/dbs/{db}/colls",
            )
        if operation in {"columns", "dump"}:
            container = quote(_target_table(target, table), safe="")
            limit = int(kwargs.get("limit", 25 if operation == "dump" else 1))
            columns = list(kwargs.get("columns") or [])
            projection = ", ".join(f"c.{column}" for column in columns) if columns else "*"
            query = f"SELECT TOP {limit} {projection} FROM c"
            return _http_request(
                target,
                operation=operation,
                action="query_documents",
                method="POST",
                path=f"/dbs/{db}/colls/{container}/docs",
                body={"query": query, "parameters": []},
                headers={
                    "Content-Type": "application/query+json",
                    "x-ms-documentdb-isquery": "true",
                },
            )
        raise ValueError(f"Unsupported Cosmos DB direct operation: {operation}")

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if not isinstance(data, Mapping):
            return {}
        if operation == "databases":
            return {"databases": _resource_ids(data.get("Databases", data.get("databases", [])))}
        if operation == "tables":
            resources = data.get(
                "DocumentCollections", data.get("Collections", data.get("colls", []))
            )
            return {"tables": _resource_ids(resources)}
        docs = [
            dict(item)
            for item in data.get("Documents", data.get("documents", []))
            if isinstance(item, Mapping)
        ]
        if operation == "columns":
            return {
                "columns": sorted(set().union(*(_nested_keys(doc) for doc in docs))) if docs else []
            }
        if operation == "dump":
            return {"rows": docs}
        return {}


def _resource_ids(resources: Any) -> list[str]:
    if isinstance(resources, list):
        return [
            str(item.get("id") or item.get("_rid") or item.get("name"))
            for item in resources
            if isinstance(item, Mapping)
            and (item.get("id") or item.get("_rid") or item.get("name"))
        ]
    return _strings(resources)


class MongoDBDirectAdapter(DirectServiceAdapterBase):
    capabilities = DirectAdapterCapabilities(
        backend="mongodb",
        family="nosql",
        aliases=("mongodb", "mongo", "mongod"),
        operations=_OPERATIONS,
        transports=("http", "mongodb"),
        description="Builds MongoDB HTTP diagnostic/REST probes and wire command shapes.",
    )

    def build_request(
        self, target: DirectTarget, operation: str, **kwargs: Any
    ) -> DirectServiceRequest:
        database = kwargs.get("database") or target.database
        table = kwargs.get("table") or kwargs.get("collection") or target.table
        limit = int(kwargs.get("limit", 25 if operation == "dump" else 1))

        endpoint = (target.endpoint or "").strip()
        is_mongo_wire = endpoint.startswith(("mongodb://", "mongodb+srv://")) or bool(
            target.options.get("wire")
        )

        if is_mongo_wire:
            if operation == "databases":
                return DirectServiceRequest(
                    operation=operation,
                    transport="mongodb",
                    action="listDatabases",
                    command=("listDatabases",),
                    body={"listDatabases": 1, "nameOnly": True},
                    database="admin",
                )
            if not database:
                raise ValueError(
                    "MongoDB direct operations require a database except for databases."
                )
            if operation == "tables":
                return DirectServiceRequest(
                    operation=operation,
                    transport="mongodb",
                    action="listCollections",
                    command=("listCollections",),
                    body={"listCollections": 1, "nameOnly": True},
                    database=database,
                )
            if operation in {"columns", "dump"}:
                collection = _target_table(target, table)
                return DirectServiceRequest(
                    operation=operation,
                    transport="mongodb",
                    action="find",
                    command=("find", collection),
                    body={"find": collection, "limit": limit, "filter": {}},
                    database=database,
                    table=collection,
                )
            raise ValueError(f"Unsupported MongoDB direct operation: {operation}")

        if operation == "databases":
            return _http_request(
                target,
                operation=operation,
                action="list_databases",
                method="GET",
                path="/_status",
                params={"listDatabases": "1"},
                headers={"Accept": "application/json"},
            )
        if not database:
            raise ValueError(
                "MongoDB direct operations require a database except for databases."
            )
        db = quote(str(database), safe="")
        if operation == "tables":
            return _http_request(
                target,
                operation=operation,
                action="list_collections",
                method="GET",
                path=f"/{db}/_collections",
                headers={"Accept": "application/json"},
                database=database,
            )
        if operation in {"columns", "dump"}:
            collection = quote(_target_table(target, table), safe="")
            columns = list(kwargs.get("columns") or [])
            projection = {col: 1 for col in columns} if columns else {}
            body: dict[str, Any] = {"limit": limit}
            if projection:
                body["projection"] = projection
            return _http_request(
                target,
                operation=operation,
                action="find_documents",
                method="GET" if operation == "dump" and not columns else "POST",
                path=f"/{db}/{collection}",
                body=body,
                params={"limit": str(limit)} if operation == "dump" else {},
                headers={"Accept": "application/json", "Content-Type": "application/json"},
                database=database,
                table=str(table),
            )
        raise ValueError(f"Unsupported MongoDB direct operation: {operation}")

    def parse_response(
        self, operation: str, raw: Any, request: DirectServiceRequest
    ) -> dict[str, Any]:
        data = _json(raw)
        if not isinstance(data, (Mapping, list)):
            return {}

        if operation == "databases":
            if isinstance(data, list):
                return {"databases": _strings(data)}
            if "databases" in data:
                dbs = data["databases"]
                if isinstance(dbs, list):
                    return {
                        "databases": [
                            str(item.get("name", item))
                            for item in dbs
                            if (isinstance(item, Mapping) and "name" in item)
                            or isinstance(item, str)
                        ]
                    }
            if "dbs" in data and isinstance(data["dbs"], list):
                return {"databases": [str(item.get("name", item)) for item in data["dbs"]]}
            return {"databases": _strings(data.get("names", []))}

        if operation == "tables":
            if isinstance(data, list):
                return {"tables": _strings(data)}
            cursor = data.get("cursor")
            if isinstance(cursor, Mapping) and "firstBatch" in cursor:
                batch = cursor.get("firstBatch", [])
                if isinstance(batch, list):
                    return {
                        "tables": [
                            str(item.get("name", item))
                            for item in batch
                            if (isinstance(item, Mapping) and "name" in item)
                            or isinstance(item, str)
                        ]
                    }
            if "collections" in data and isinstance(data["collections"], list):
                return {
                    "tables": [
                        str(item.get("name", item))
                        for item in data["collections"]
                        if (isinstance(item, Mapping) and "name" in item)
                        or isinstance(item, str)
                    ]
                }
            return {"tables": _strings(data.get("names", []))}

        docs: list[dict[str, Any]] = []
        if isinstance(data, list):
            docs = [dict(item) for item in data if isinstance(item, Mapping)]
        elif isinstance(data, Mapping):
            cursor = data.get("cursor")
            if isinstance(cursor, Mapping) and "firstBatch" in cursor:
                batch = cursor.get("firstBatch", [])
                if isinstance(batch, list):
                    docs = [dict(item) for item in batch if isinstance(item, Mapping)]
            elif "documents" in data and isinstance(data["documents"], list):
                docs = [dict(item) for item in data["documents"] if isinstance(item, Mapping)]
            elif "rows" in data and isinstance(data["rows"], list):
                docs = [dict(item) for item in data["rows"] if isinstance(item, Mapping)]
            elif "data" in data and isinstance(data["data"], list):
                docs = [dict(item) for item in data["data"] if isinstance(item, Mapping)]
            else:
                docs = [dict(data)]

        if operation == "columns":
            return {
                "columns": sorted(
                    set().union(*(_nested_keys(doc, skip_private=False) for doc in docs))
                )
                if docs
                else []
            }
        if operation == "dump":
            return {"rows": docs}
        return {}


__all__ = [
    "CassandraDirectAdapter",
    "CosmosDBDirectAdapter",
    "CouchDBDirectAdapter",
    "DynamoDBDirectAdapter",
    "MongoDBDirectAdapter",
    "Neo4jDirectAdapter",
    "RedisDirectAdapter",
    "SearchDirectAdapter",
]
