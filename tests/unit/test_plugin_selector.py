from stealthix.plugins.selector import select_plugin


def test_select_plugin_by_hint():
    plugin = select_plugin("mysql")
    assert plugin and plugin.name == "mysql"


def test_select_plugin_by_fingerprint():
    plugin = select_plugin(None, "Postgres syntax error")
    assert plugin and plugin.name == "postgresql"
