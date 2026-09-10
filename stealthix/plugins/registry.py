"""
Plugin registry for discovering and managing Stealthix plugins.

This module provides a centralized registry for internal and external plugins,
supporting discovery via entry_points and manual registration.
"""

from __future__ import annotations

import importlib
import importlib.metadata
import os
import threading
from collections.abc import Iterable
from typing import Any

import structlog

from stealthix.plugins.base import Plugin

logger = structlog.get_logger(__name__)


class PluginRegistry:
    """Central registry for Stealthix plugins."""

    def __init__(self) -> None:
        """Initialize plugin registry."""
        self._plugins: dict[str, Plugin] = {}
        self._internal_plugins: list[Plugin] = []
        self._external_plugins: list[Plugin] = []
        self._errors: list[dict[str, str]] = []
        self._internal_discovered = False
        self._external_discovered = False
        self._configured_discovered = False

    def register(self, plugin: Plugin, *, source: str = "manual") -> bool:
        """
        Register a plugin.

        Args:
            plugin: Plugin instance to register
        """
        errors = self.validate_plugin(plugin)
        if errors:
            self._record_error(
                "plugin_invalid",
                source=source,
                plugin=str(getattr(plugin, "name", "<unknown>")),
                error="; ".join(errors),
            )
            return False

        key = self._plugin_key(plugin.name)
        if key in self._plugins:
            existing = self._plugins[key]
            logger.warning(
                "plugin_duplicate_ignored",
                name=key,
                existing_internal=existing.is_internal,
                incoming_internal=plugin.is_internal,
                source=source,
            )
            return False
        self._plugins[key] = plugin
        if plugin.is_internal:
            self._internal_plugins.append(plugin)
        else:
            self._external_plugins.append(plugin)
        logger.info(
            "plugin_registered",
            name=plugin.name,
            dbms=plugin.dbms,
            is_internal=plugin.is_internal,
            source=source,
        )
        return True

    def get(self, name: str) -> Plugin | None:
        """
        Get plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin instance or None if not found
        """
        return self._plugins.get(self._plugin_key(name))

    def get_by_dbms(self, dbms: str) -> list[Plugin]:
        """
        Get all plugins for a specific DBMS.

        Args:
            dbms: Database management system name

        Returns:
            List of plugins for the DBMS
        """
        return [p for p in self._plugins.values() if p.dbms and p.dbms.lower() == dbms.lower()]

    def get_all(self) -> list[Plugin]:
        """
        Get all registered plugins.

        Returns:
            List of all plugins
        """
        return list(self._plugins.values())

    def get_internal(self) -> list[Plugin]:
        """
        Get all internal plugins.

        Returns:
            List of internal plugins
        """
        return self._internal_plugins.copy()

    def get_external(self) -> list[Plugin]:
        """
        Get all external plugins.

        Returns:
            List of external plugins
        """
        return self._external_plugins.copy()

    def get_errors(self) -> list[dict[str, str]]:
        """Get non-fatal discovery/validation errors."""
        return self._errors.copy()

    def discover_internal(self, plugin_lists: list[list[Plugin]]) -> None:
        """
        Discover and register internal plugins from plugin lists.

        Args:
            plugin_lists: List of plugin lists (SQL_PLUGINS, NOSQL_PLUGINS, etc.)
        """
        if self._internal_discovered:
            return
        for plugin_list in plugin_lists:
            for plugin in plugin_list:
                plugin.is_internal = True
                self.register(plugin, source="internal")
        self._internal_discovered = True

    def discover_external(self) -> None:
        """
        Discover external plugins via entry_points.

        Uses importlib.metadata to discover plugins registered via
        the 'stealthix.plugins' entry point group.
        """
        if self._external_discovered:
            return
        try:
            entry_points = importlib.metadata.entry_points()
            if hasattr(entry_points, "select"):
                # Python 3.10+
                stealthix_entries = entry_points.select(group="stealthix.plugins")
            else:
                # Python 3.9
                stealthix_entries = entry_points.get("stealthix.plugins", [])

            for entry in sorted(
                stealthix_entries,
                key=lambda ep: (str(getattr(ep, "name", "")), str(getattr(ep, "value", ""))),
            ):
                try:
                    plugin = self._coerce_plugin(entry.load())
                    if plugin is not None:
                        plugin.is_internal = False
                        self.register(plugin, source=f"entry-point:{entry.name}")
                    else:
                        self._record_error(
                            "plugin_invalid",
                            source=f"entry-point:{entry.name}",
                            plugin=str(getattr(entry, "name", "<unknown>")),
                            error="entry point did not resolve to a Plugin",
                        )
                except Exception as e:
                    self._record_error(
                        "plugin_load_failed",
                        source=f"entry-point:{getattr(entry, 'name', '<unknown>')}",
                        plugin=str(getattr(entry, "name", "<unknown>")),
                        error=self._safe_error(e),
                    )
        except Exception as e:
            self._record_error(
                "external_plugin_discovery_failed",
                source="entry-points",
                plugin="<discovery>",
                error=self._safe_error(e),
            )
        finally:
            self._external_discovered = True

    def discover_configured(self, specs: Iterable[str] | str | None = None) -> None:
        """Discover external plugins from import specs.

        Specs use ``module:attribute`` or ``module.attribute`` and may resolve to a
        Plugin instance, Plugin subclass, or an iterable of those values.
        """
        if self._configured_discovered and specs is None:
            return
        raw_specs = self._parse_specs(specs)
        for spec in sorted(dict.fromkeys(raw_specs)):
            try:
                loaded = self._load_spec(spec)
                for plugin in self._iter_plugins(loaded):
                    plugin.is_internal = False
                    self.register(plugin, source=f"configured:{spec}")
            except Exception as e:
                self._record_error(
                    "configured_plugin_load_failed",
                    source=f"configured:{spec}",
                    plugin=spec,
                    error=self._safe_error(e),
                )
        if specs is None:
            self._configured_discovered = True

    @staticmethod
    def validate_plugin(plugin: Any) -> list[str]:
        """Validate the public Plugin contract."""
        if not isinstance(plugin, Plugin):
            return ["not a Plugin instance"]
        errors: list[str] = []
        if not isinstance(plugin.name, str) or not plugin.name.strip():
            errors.append("missing name")
        if not isinstance(plugin.family, str) or not plugin.family.strip():
            errors.append("missing family")
        if plugin.dbms is not None and not isinstance(plugin.dbms, str):
            errors.append("dbms must be a string or None")
        for attr in (
            "payloads",
            "fingerprints",
            "error_signatures",
            "version_queries",
            "privilege_checks",
            "os_queries",
        ):
            value = getattr(plugin, attr, None)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                errors.append(f"{attr} must be a list of strings")
        if plugin.preferred_techniques is not None and not isinstance(
            plugin.preferred_techniques, str
        ):
            errors.append("preferred_techniques must be a string or None")
        if not isinstance(plugin.extraction_profiles, dict):
            errors.append("extraction_profiles must be a dict")
        if not callable(getattr(plugin, "apply", None)):
            errors.append("apply must be callable")
        return errors

    def validate_plugins(self) -> list[str]:
        """
        Validate all registered plugins.

        Returns:
            List of validation errors (empty if all valid)
        """
        errors: list[str] = []
        for name, plugin in self._plugins.items():
            for error in self.validate_plugin(plugin):
                errors.append(f"Plugin {name}: {error}")
        return errors

    def check_conflicts(self) -> dict[str, list[str]]:
        """
        Check for plugin conflicts.

        Returns:
            Dictionary mapping DBMS to list of conflicting plugin names
        """
        conflicts: dict[str, list[str]] = {}
        for dbms in {p.dbms for p in self._plugins.values() if p.dbms}:
            dbms_plugins = self.get_by_dbms(dbms)
            if len(dbms_plugins) > 1:
                conflicts[dbms] = [p.name for p in dbms_plugins]
        return conflicts

    @staticmethod
    def _plugin_key(name: str) -> str:
        return (name or "").strip().lower()

    @staticmethod
    def _safe_error(error: Exception) -> str:
        message = str(error).strip()
        if len(message) > 300:
            message = f"{message[:297]}..."
        return f"{error.__class__.__name__}: {message}" if message else error.__class__.__name__

    def _record_error(self, code: str, *, source: str, plugin: str, error: str) -> None:
        event = {"code": code, "source": source, "plugin": plugin, "error": error}
        self._errors.append(event)
        logger.warning("plugin_registry_error", **event)

    @staticmethod
    def _coerce_plugin(value: Any) -> Plugin | None:
        if isinstance(value, Plugin):
            return value
        if isinstance(value, type) and issubclass(value, Plugin):
            return value()
        return None

    def _iter_plugins(self, value: Any) -> Iterable[Plugin]:
        plugin = self._coerce_plugin(value)
        if plugin is not None:
            yield plugin
            return
        if isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict)):
            for item in value:
                plugin = self._coerce_plugin(item)
                if plugin is None:
                    self._record_error(
                        "plugin_invalid",
                        source="configured",
                        plugin=repr(item),
                        error="configured iterable contained a non-Plugin value",
                    )
                    continue
                yield plugin
            return
        raise TypeError("configured spec did not resolve to a Plugin or iterable of Plugins")

    @staticmethod
    def _parse_specs(specs: Iterable[str] | str | None) -> list[str]:
        if specs is None:
            specs = os.environ.get("STEALTHIX_PLUGIN_SPECS", "")
        if isinstance(specs, str):
            pieces = specs.replace(";", ",").split(",")
        else:
            pieces = list(specs)
        return [str(piece).strip() for piece in pieces if str(piece).strip()]

    @staticmethod
    def _load_spec(spec: str) -> Any:
        module_name, sep, attr = spec.partition(":")
        if not sep:
            module_name, dot, attr = spec.rpartition(".")
            if not dot:
                raise ValueError("plugin spec must use module:attribute or module.attribute")
        module = importlib.import_module(module_name)
        value: Any = module
        for part in attr.split("."):
            if not part:
                raise ValueError("plugin spec contains an empty attribute segment")
            value = getattr(value, part)
        return value


# Global singleton instance
_global_registry: PluginRegistry | None = None
_registry_lock = threading.Lock()


def get_plugin_registry() -> PluginRegistry:
    """Get global plugin registry singleton."""
    global _global_registry
    if _global_registry is None:
        with _registry_lock:
            if _global_registry is None:
                _global_registry = PluginRegistry()
    return _global_registry


def reset_plugin_registry() -> None:
    """Reset global plugin registry (for testing)."""
    global _global_registry
    with _registry_lock:
        _global_registry = None
