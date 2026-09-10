from __future__ import annotations

from stealthix.plugins.base import Plugin
from stealthix.plugins.newsql import NEWSQL_PLUGINS
from stealthix.plugins.nosql import NOSQL_PLUGINS
from stealthix.plugins.registry import get_plugin_registry
from stealthix.plugins.sql import SQL_PLUGINS


def all_plugins() -> list[Plugin]:
    """Get all registered plugins (internal + external)."""
    registry = get_plugin_registry()
    registry.discover_internal([SQL_PLUGINS, NOSQL_PLUGINS, NEWSQL_PLUGINS])
    registry.discover_configured()
    registry.discover_external()
    return registry.get_all()
