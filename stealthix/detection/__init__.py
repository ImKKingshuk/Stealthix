from __future__ import annotations

from importlib import import_module

__all__ = [
    "detect_sqli",
    "detect_nosqli",
    "detect_newsql",
    "detect_idor",
    "detect_websocket",
    "detect_graphql",
    "detect_graphqli",
    "detect_searchqli",
    "detect_timeseriesqli",
]

_EXPORTS = {
    "detect_sqli": ("stealthix.detection.sqli", "detect_sqli"),
    "detect_nosqli": ("stealthix.detection.nosqli", "detect_nosqli"),
    "detect_newsql": ("stealthix.detection.newsql", "detect_newsql"),
    "detect_idor": ("stealthix.detection.common", "detect_idor"),
    "detect_websocket": ("stealthix.detection.websocket", "detect_websocket"),
    "detect_graphql": ("stealthix.detection.graphql", "detect_graphql"),
    "detect_graphqli": ("stealthix.detection.graphqli", "detect_graphqli"),
    "detect_searchqli": ("stealthix.detection.searchqli", "detect_searchqli"),
    "detect_timeseriesqli": ("stealthix.detection.timeseriesqli", "detect_timeseriesqli"),
}


def __getattr__(name: str):
    if name not in _EXPORTS:
        raise AttributeError(name)
    module_name, attr_name = _EXPORTS[name]
    return getattr(import_module(module_name), attr_name)
