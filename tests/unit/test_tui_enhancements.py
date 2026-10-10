from __future__ import annotations

from stealthix._tui_runtime.constants import SUPPORTED_DBMS, SUPPORTED_REPORT_FORMATS


def test_tui_constants_dynamically_populated() -> None:
    assert "auto" in SUPPORTED_DBMS
    assert "mysql" in SUPPORTED_DBMS
    assert "clickhouse" in SUPPORTED_DBMS
    assert "snowflake" in SUPPORTED_DBMS
    assert "duckdb" in SUPPORTED_DBMS
    assert "mongodb" in SUPPORTED_DBMS
    assert "cockroachdb" in SUPPORTED_DBMS
    assert len(SUPPORTED_DBMS) >= 50

    assert "csv" in SUPPORTED_REPORT_FORMATS
    assert "json" in SUPPORTED_REPORT_FORMATS
    assert "markdown" in SUPPORTED_REPORT_FORMATS
