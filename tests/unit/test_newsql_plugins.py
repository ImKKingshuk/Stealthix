"""Unit tests for NewSQL plugins."""

from __future__ import annotations

import pytest

from stealthix.plugins.base import Plugin
from stealthix.plugins.newsql import NEWSQL_PLUGINS


class TestNewSQLPlugins:
    """Test NewSQL plugin configuration and extraction profiles."""

    def test_all_plugins_have_required_attributes(self) -> None:
        """Test that all NewSQL plugins have required attributes."""
        required_attrs = [
            "name",
            "family",
            "dbms",
            "payloads",
            "fingerprints",
            "error_signatures",
            "version_queries",
            "privilege_checks",
            "os_queries",
            "preferred_techniques",
            "extraction_profiles",
        ]
        for plugin in NEWSQL_PLUGINS:
            for attr in required_attrs:
                assert hasattr(plugin, attr), f"Plugin {plugin.name} missing attribute {attr}"

    def test_all_plugins_have_newsql_family(self) -> None:
        """Test that all plugins have family='newsql'."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.family == "newsql", (
                f"Plugin {plugin.name} has family {plugin.family}, expected 'newsql'"
            )

    def test_expected_databases_exist(self) -> None:
        """Test that expected NewSQL databases are present."""
        plugin_names = {plugin.name for plugin in NEWSQL_PLUGINS}
        expected_databases = {
            "cockroachdb",
            "tidb",
            "yugabytedb",
            "spanner",
            "voltdb",
            "nuodb",
            "singlestore",
            "oceanbase",
            "polardb",
            "tiflash",
            "yugabyte_ycql",
        }
        for db in expected_databases:
            assert db in plugin_names, f"Expected database {db} not found in NewSQL plugins"

    def test_spanner_has_extraction_profiles(self) -> None:
        """Test that Spanner has extraction profiles."""
        spanner = next((p for p in NEWSQL_PLUGINS if p.name == "spanner"), None)
        assert spanner is not None, "Spanner plugin not found"
        assert spanner.extraction_profiles, "Spanner missing extraction profiles"
        assert "databases" in spanner.extraction_profiles
        assert "tables" in spanner.extraction_profiles
        assert "columns" in spanner.extraction_profiles
        assert "dump" in spanner.extraction_profiles

    def test_voltdb_has_extraction_profiles(self) -> None:
        """Test that VoltDB has extraction profiles."""
        voltdb = next((p for p in NEWSQL_PLUGINS if p.name == "voltdb"), None)
        assert voltdb is not None, "VoltDB plugin not found"
        assert voltdb.extraction_profiles, "VoltDB missing extraction profiles"
        assert "databases" in voltdb.extraction_profiles
        assert "tables" in voltdb.extraction_profiles
        assert "columns" in voltdb.extraction_profiles
        assert "dump" in voltdb.extraction_profiles

    def test_nuodb_has_extraction_profiles(self) -> None:
        """Test that NuoDB has extraction profiles."""
        nuodb = next((p for p in NEWSQL_PLUGINS if p.name == "nuodb"), None)
        assert nuodb is not None, "NuoDB plugin not found"
        assert nuodb.extraction_profiles, "NuoDB missing extraction profiles"
        assert "databases" in nuodb.extraction_profiles
        assert "tables" in nuodb.extraction_profiles
        assert "columns" in nuodb.extraction_profiles
        assert "dump" in nuodb.extraction_profiles

    def test_singlestore_has_extraction_profiles(self) -> None:
        """Test that SingleStore has extraction profiles."""
        singlestore = next((p for p in NEWSQL_PLUGINS if p.name == "singlestore"), None)
        assert singlestore is not None, "SingleStore plugin not found"
        assert singlestore.extraction_profiles, "SingleStore missing extraction profiles"
        assert "databases" in singlestore.extraction_profiles
        assert "tables" in singlestore.extraction_profiles
        assert "columns" in singlestore.extraction_profiles
        assert "dump" in singlestore.extraction_profiles
        assert "files" in singlestore.extraction_profiles

    def test_oceanbase_has_extraction_profiles(self) -> None:
        """Test that OceanBase has extraction profiles."""
        oceanbase = next((p for p in NEWSQL_PLUGINS if p.name == "oceanbase"), None)
        assert oceanbase is not None, "OceanBase plugin not found"
        assert oceanbase.extraction_profiles, "OceanBase missing extraction profiles"
        assert "databases" in oceanbase.extraction_profiles
        assert "tables" in oceanbase.extraction_profiles
        assert "columns" in oceanbase.extraction_profiles
        assert "dump" in oceanbase.extraction_profiles
        assert "files" in oceanbase.extraction_profiles

    def test_polardb_has_extraction_profiles(self) -> None:
        """Test that PolarDB has extraction profiles."""
        polardb = next((p for p in NEWSQL_PLUGINS if p.name == "polardb"), None)
        assert polardb is not None, "PolarDB plugin not found"
        assert polardb.extraction_profiles, "PolarDB missing extraction profiles"
        assert "databases" in polardb.extraction_profiles
        assert "tables" in polardb.extraction_profiles
        assert "columns" in polardb.extraction_profiles
        assert "dump" in polardb.extraction_profiles
        assert "files" in polardb.extraction_profiles

    def test_tiflash_has_extraction_profiles(self) -> None:
        """Test that TiFlash has extraction profiles."""
        tiflash = next((p for p in NEWSQL_PLUGINS if p.name == "tiflash"), None)
        assert tiflash is not None, "TiFlash plugin not found"
        assert tiflash.extraction_profiles, "TiFlash missing extraction profiles"
        assert "databases" in tiflash.extraction_profiles
        assert "tables" in tiflash.extraction_profiles
        assert "columns" in tiflash.extraction_profiles
        assert "dump" in tiflash.extraction_profiles
        assert "files" in tiflash.extraction_profiles

    def test_yugabyte_ycql_has_extraction_profiles(self) -> None:
        """Test that YugabyteDB YCQL has extraction profiles."""
        ycql = next((p for p in NEWSQL_PLUGINS if p.name == "yugabyte_ycql"), None)
        assert ycql is not None, "YugabyteDB YCQL plugin not found"
        assert ycql.extraction_profiles, "YugabyteDB YCQL missing extraction profiles"
        assert "databases" in ycql.extraction_profiles
        assert "tables" in ycql.extraction_profiles
        assert "columns" in ycql.extraction_profiles
        assert "dump" in ycql.extraction_profiles

    def test_extraction_profiles_have_payloads(self) -> None:
        """Test that extraction profiles have payloads."""
        for plugin in NEWSQL_PLUGINS:
            for operation, profile in plugin.extraction_profiles.items():
                assert "payloads" in profile, (
                    f"Plugin {plugin.name} operation {operation} missing payloads"
                )
                assert profile["payloads"], (
                    f"Plugin {plugin.name} operation {operation} has empty payloads"
                )

    def test_extraction_profiles_have_patterns(self) -> None:
        """Test that enumeration extraction profiles have patterns."""
        enum_operations = {"databases", "tables", "columns"}
        for plugin in NEWSQL_PLUGINS:
            for operation, profile in plugin.extraction_profiles.items():
                if operation in enum_operations:
                    assert "patterns" in profile, (
                        f"Plugin {plugin.name} operation {operation} missing patterns"
                    )
                    assert profile["patterns"], (
                        f"Plugin {plugin.name} operation {operation} has empty patterns"
                    )

    def test_plugins_have_version_queries(self) -> None:
        """Test that plugins have version queries."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.version_queries, f"Plugin {plugin.name} missing version queries"
            assert plugin.version_queries, f"Plugin {plugin.name} has empty version queries"

    def test_plugins_have_privilege_checks(self) -> None:
        """Test that plugins have privilege checks."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.privilege_checks, f"Plugin {plugin.name} missing privilege checks"
            assert plugin.privilege_checks, f"Plugin {plugin.name} has empty privilege checks"

    def test_plugins_have_error_signatures(self) -> None:
        """Test that plugins have error signatures."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.error_signatures, f"Plugin {plugin.name} missing error signatures"
            assert plugin.error_signatures, f"Plugin {plugin.name} has empty error signatures"

    def test_plugins_have_fingerprints(self) -> None:
        """Test that plugins have fingerprints."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.fingerprints, f"Plugin {plugin.name} missing fingerprints"
            assert plugin.fingerprints, f"Plugin {plugin.name} has empty fingerprints"

    def test_plugins_have_payloads(self) -> None:
        """Test that plugins have payloads."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.payloads, f"Plugin {plugin.name} missing payloads"
            assert plugin.payloads, f"Plugin {plugin.name} has empty payloads"

    def test_plugins_have_preferred_techniques(self) -> None:
        """Test that plugins have preferred techniques."""
        for plugin in NEWSQL_PLUGINS:
            assert plugin.preferred_techniques, f"Plugin {plugin.name} missing preferred techniques"

    def test_singlestore_memsql_alias_in_fingerprints(self) -> None:
        """Test that SingleStore includes memsql in fingerprints for compatibility."""
        singlestore = next((p for p in NEWSQL_PLUGINS if p.name == "singlestore"), None)
        assert singlestore is not None, "SingleStore plugin not found"
        assert "memsql" in singlestore.fingerprints, (
            "SingleStore should include memsql in fingerprints for compatibility"
        )
        assert "singlestore" in singlestore.fingerprints, (
            "SingleStore should include singlestore in fingerprints"
        )

    def test_yugabyte_ycql_cassandra_fingerprint(self) -> None:
        """Test that YugabyteDB YCQL includes cassandra in error signatures."""
        ycql = next((p for p in NEWSQL_PLUGINS if p.name == "yugabyte_ycql"), None)
        assert ycql is not None, "YugabyteDB YCQL plugin not found"
        assert "cassandra" in ycql.error_signatures, (
            "YugabyteDB YCQL should include cassandra in error signatures for compatibility"
        )
        assert "ycql" in ycql.error_signatures, (
            "YugabyteDB YCQL should include ycql in error signatures"
        )
