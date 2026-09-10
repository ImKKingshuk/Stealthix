from __future__ import annotations

from unittest.mock import Mock, patch

import pytest

from stealthix.plugins.nosql.document import DOCUMENT_PLUGINS
from stealthix.plugins.nosql.graph import GRAPH_PLUGINS
from stealthix.plugins.nosql.keyvalue import KEYVALUE_PLUGINS
from stealthix.plugins.nosql.multimodel import MULTIMODEL_PLUGINS
from stealthix.plugins.nosql.search import SEARCH_PLUGINS
from stealthix.plugins.nosql.timeseries import TIMESERIES_PLUGINS


class TestDocumentPlugins:
    def test_arangodb_plugin_exists(self):
        """Test that ArangoDB plugin is defined."""
        plugins = [p for p in DOCUMENT_PLUGINS if p.dbms == "arangodb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "arangodb"
        assert plugin.family == "nosql"
        assert len(plugin.payloads) > 0
        assert len(plugin.fingerprints) > 0
        assert len(plugin.error_signatures) > 0

    def test_arangodb_extraction_profiles(self):
        """Test that ArangoDB has extraction profiles."""
        plugins = [p for p in DOCUMENT_PLUGINS if p.dbms == "arangodb"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles
        assert "columns" in plugin.extraction_profiles
        assert "dump" in plugin.extraction_profiles

    def test_couchbase_plugin_exists(self):
        """Test that Couchbase plugin is defined."""
        plugins = [p for p in DOCUMENT_PLUGINS if p.dbms == "couchbase"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "couchbase"
        assert plugin.family == "nosql"
        assert len(plugin.payloads) > 0

    def test_rethinkdb_plugin_exists(self):
        """Test that RethinkDB plugin is defined."""
        plugins = [p for p in DOCUMENT_PLUGINS if p.dbms == "rethinkdb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "rethinkdb"
        assert plugin.family == "nosql"

    def test_orientdb_plugin_exists(self):
        """Test that OrientDB plugin is defined."""
        plugins = [p for p in DOCUMENT_PLUGINS if p.dbms == "orientdb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "orientdb"
        assert plugin.family == "nosql"


class TestGraphPlugins:
    def test_neo4j_plugin_exists(self):
        """Test that Neo4j plugin is defined."""
        plugins = [p for p in GRAPH_PLUGINS if p.dbms == "neo4j"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "neo4j"
        assert plugin.family == "nosql"
        assert len(plugin.payloads) > 0

    def test_neo4j_extraction_profiles(self):
        """Test that Neo4j has extraction profiles."""
        plugins = [p for p in GRAPH_PLUGINS if p.dbms == "neo4j"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles

    def test_janusgraph_plugin_exists(self):
        """Test that JanusGraph plugin is defined."""
        plugins = [p for p in GRAPH_PLUGINS if p.dbms == "janusgraph"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "janusgraph"
        assert plugin.family == "nosql"

    def test_neptune_plugin_exists(self):
        """Test that Neptune plugin is defined."""
        plugins = [p for p in GRAPH_PLUGINS if p.dbms == "neptune"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "neptune"
        assert plugin.family == "nosql"


class TestSearchPlugins:
    def test_elasticsearch_plugin_exists(self):
        """Test that Elasticsearch plugin is defined."""
        plugins = [p for p in SEARCH_PLUGINS if p.dbms == "elasticsearch"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "elasticsearch"
        assert plugin.family == "nosql"

    def test_elasticsearch_extraction_profiles(self):
        """Test that Elasticsearch has extraction profiles."""
        plugins = [p for p in SEARCH_PLUGINS if p.dbms == "elasticsearch"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles

    def test_solr_plugin_exists(self):
        """Test that Solr plugin is defined."""
        plugins = [p for p in SEARCH_PLUGINS if p.dbms == "solr"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "solr"
        assert plugin.family == "nosql"

    def test_opensearch_plugin_exists(self):
        """Test that OpenSearch plugin is defined."""
        plugins = [p for p in SEARCH_PLUGINS if p.dbms == "opensearch"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "opensearch"
        assert plugin.family == "nosql"


class TestTimeSeriesPlugins:
    def test_influxdb_plugin_exists(self):
        """Test that InfluxDB plugin is defined."""
        plugins = [p for p in TIMESERIES_PLUGINS if p.dbms == "influxdb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "influxdb"
        assert plugin.family == "nosql"

    def test_influxdb_extraction_profiles(self):
        """Test that InfluxDB has extraction profiles."""
        plugins = [p for p in TIMESERIES_PLUGINS if p.dbms == "influxdb"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles

    def test_prometheus_plugin_exists(self):
        """Test that Prometheus plugin is defined."""
        plugins = [p for p in TIMESERIES_PLUGINS if p.dbms == "prometheus"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "prometheus"
        assert plugin.family == "nosql"


class TestKeyValuePlugins:
    def test_aerospike_plugin_exists(self):
        """Test that Aerospike plugin is defined."""
        plugins = [p for p in KEYVALUE_PLUGINS if p.dbms == "aerospike"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "aerospike"
        assert plugin.family == "nosql"

    def test_aerospike_extraction_profiles(self):
        """Test that Aerospike has extraction profiles."""
        plugins = [p for p in KEYVALUE_PLUGINS if p.dbms == "aerospike"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles

    def test_riak_plugin_exists(self):
        """Test that Riak plugin is defined."""
        plugins = [p for p in KEYVALUE_PLUGINS if p.dbms == "riak"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "riak"
        assert plugin.family == "nosql"


class TestMultiModelPlugins:
    def test_cosmosdb_plugin_exists(self):
        """Test that Cosmos DB plugin is defined."""
        plugins = [p for p in MULTIMODEL_PLUGINS if p.dbms == "cosmosdb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "cosmosdb"
        assert plugin.family == "nosql"

    def test_cosmosdb_extraction_profiles(self):
        """Test that Cosmos DB has extraction profiles."""
        plugins = [p for p in MULTIMODEL_PLUGINS if p.dbms == "cosmosdb"]
        plugin = plugins[0]
        assert plugin.extraction_profiles is not None
        assert "databases" in plugin.extraction_profiles
        assert "tables" in plugin.extraction_profiles

    def test_documentdb_plugin_exists(self):
        """Test that DocumentDB plugin is defined."""
        plugins = [p for p in MULTIMODEL_PLUGINS if p.dbms == "documentdb"]
        assert len(plugins) == 1
        plugin = plugins[0]
        assert plugin.name == "documentdb"
        assert plugin.family == "nosql"


class TestPluginStructure:
    def test_all_plugins_have_required_fields(self):
        """Test that all plugins have required fields."""
        all_plugins = (
            DOCUMENT_PLUGINS
            + GRAPH_PLUGINS
            + SEARCH_PLUGINS
            + TIMESERIES_PLUGINS
            + KEYVALUE_PLUGINS
            + MULTIMODEL_PLUGINS
        )
        for plugin in all_plugins:
            assert plugin.name is not None
            assert plugin.family == "nosql"
            assert plugin.dbms is not None
            assert len(plugin.payloads) > 0
            assert len(plugin.fingerprints) > 0
            assert len(plugin.error_signatures) > 0

    def test_all_plugins_have_version_queries(self):
        """Test that all plugins have version queries."""
        all_plugins = (
            DOCUMENT_PLUGINS
            + GRAPH_PLUGINS
            + SEARCH_PLUGINS
            + TIMESERIES_PLUGINS
            + KEYVALUE_PLUGINS
            + MULTIMODEL_PLUGINS
        )
        for plugin in all_plugins:
            assert len(plugin.version_queries) > 0

    def test_all_plugins_have_privilege_checks(self):
        """Test that all plugins have privilege checks."""
        all_plugins = (
            DOCUMENT_PLUGINS
            + GRAPH_PLUGINS
            + SEARCH_PLUGINS
            + TIMESERIES_PLUGINS
            + KEYVALUE_PLUGINS
            + MULTIMODEL_PLUGINS
        )
        for plugin in all_plugins:
            assert len(plugin.privilege_checks) > 0

    def test_all_plugins_have_os_queries(self):
        """Test that all plugins have OS queries."""
        all_plugins = (
            DOCUMENT_PLUGINS
            + GRAPH_PLUGINS
            + SEARCH_PLUGINS
            + TIMESERIES_PLUGINS
            + KEYVALUE_PLUGINS
            + MULTIMODEL_PLUGINS
        )
        for plugin in all_plugins:
            assert len(plugin.os_queries) > 0

    def test_all_plugins_have_preferred_techniques(self):
        """Test that all plugins have preferred techniques."""
        all_plugins = (
            DOCUMENT_PLUGINS
            + GRAPH_PLUGINS
            + SEARCH_PLUGINS
            + TIMESERIES_PLUGINS
            + KEYVALUE_PLUGINS
            + MULTIMODEL_PLUGINS
        )
        for plugin in all_plugins:
            assert plugin.preferred_techniques is not None
            assert len(plugin.preferred_techniques) > 0
