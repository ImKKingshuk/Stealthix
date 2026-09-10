import sys
import types

from stealthix.plugins import all_plugins
from stealthix.plugins.base import Plugin
from stealthix.plugins.registry import PluginRegistry, reset_plugin_registry


def test_plugins_list():
    plugins = all_plugins()
    names = [plugin.name for plugin in plugins]
    assert "mysql" in names
    assert "mongodb" in names
    assert "cockroachdb" in names


def test_entry_point_discovery_registers_external_plugin(monkeypatch):
    reset_plugin_registry()

    class EntryPointPlugin(Plugin):
        def __init__(self):
            super().__init__(
                name="entrydb",
                family="sql",
                dbms="entrydb",
                fingerprints=["entrydb"],
            )

    class FakeEntryPoint:
        name = "entrydb"
        value = "fake:EntryPointPlugin"

        def load(self):
            return EntryPointPlugin

    class FakeEntryPoints(list):
        def select(self, *, group):
            assert group == "stealthix.plugins"
            return self

    monkeypatch.setattr(
        "stealthix.plugins.registry.importlib.metadata.entry_points",
        lambda: FakeEntryPoints([FakeEntryPoint()]),
    )

    plugins = all_plugins()

    assert "entrydb" in [plugin.name for plugin in plugins]
    assert [plugin.name for plugin in plugins].count("entrydb") == 1
    reset_plugin_registry()


def test_configured_plugin_spec_discovers_external_plugin(monkeypatch):
    reset_plugin_registry()
    module = types.ModuleType("configured_plugin_module")
    module.CONFIGURED_PLUGIN = Plugin(
        name="configureddb",
        family="sql",
        dbms="configureddb",
        fingerprints=["configureddb"],
        is_internal=False,
    )
    monkeypatch.setitem(sys.modules, "configured_plugin_module", module)
    monkeypatch.setenv("STEALTHIX_PLUGIN_SPECS", "configured_plugin_module:CONFIGURED_PLUGIN")

    plugins = all_plugins()

    assert "configureddb" in [plugin.name for plugin in plugins]
    reset_plugin_registry()


def test_duplicate_plugin_resolution_keeps_first_registered_plugin():
    registry = PluginRegistry()
    internal = Plugin(name="dupedb", family="sql", dbms="dupedb", is_internal=True)
    external = Plugin(name="DUPEDB", family="sql", dbms="dupedb", is_internal=False)

    assert registry.register(internal, source="test-internal") is True
    assert registry.register(external, source="test-external") is False

    assert registry.get("dupedb") is internal
    assert registry.get("DUPEDB") is internal
    assert registry.get_external() == []


def test_invalid_plugin_rejected_without_raising():
    registry = PluginRegistry()
    invalid = Plugin(name="", family="sql", dbms="broken", payloads=["ok"])

    assert registry.register(invalid, source="test-invalid") is False

    assert registry.get_all() == []
    assert registry.get_errors()[0]["code"] == "plugin_invalid"
