from __future__ import annotations

from stealthix.plugins import all_plugins
from stealthix.plugins.base import Plugin
from stealthix.utils import load_rust_core


def get_plugin(name: str) -> Plugin | None:
    name = (name or "").lower()
    for plugin in all_plugins():
        if plugin.name.lower() == name:
            return plugin
    return None


def _normalize_dbms(dbms: str) -> str:
    lowered = (dbms or "").strip().lower()
    mapping = {
        "mysql": "mysql",
        "mariadb": "mariadb",
        "postgres": "postgresql",
        "postgresql": "postgresql",
        "mssql": "mssql",
        "microsoft sql server": "mssql",
        "oracle": "oracle",
        "sqlite": "sqlite",
        "mongodb": "mongodb",
        "couchdb": "couchdb",
        "cockroachdb": "cockroachdb",
        "cockroach": "cockroachdb",
        "tidb": "tidb",
        "yugabytedb": "yugabytedb",
        "spanner": "spanner",
        "redis": "redis",
        "cassandra": "cassandra",
    }
    return mapping.get(lowered, lowered)


def detect_dbms_from_response(response_text: str) -> str:
    rust = load_rust_core()
    fp_cls = rust.get("Fingerprint")
    if fp_cls:
        fp = fp_cls()
        try:
            return _normalize_dbms(fp.fingerprint_dbms(response_text))
        except Exception:
            return "unknown"
    lowered = response_text.lower()
    for name in [
        "mysql",
        "postgres",
        "oracle",
        "mssql",
        "mongodb",
        "couchdb",
        "cockroach",
        "tidb",
        "sqlite",
        "redis",
        "cassandra",
    ]:
        if name in lowered:
            return _normalize_dbms(name)
    return "unknown"


def select_plugin(dbms_hint: str | None, response_text: str | None = None) -> Plugin | None:
    if dbms_hint:
        return get_plugin(_normalize_dbms(dbms_hint))
    if response_text:
        dbms = detect_dbms_from_response(response_text)
        plugin = get_plugin(dbms)
        if plugin:
            return plugin
        for p in all_plugins():
            for token in p.fingerprints:
                if token.lower() in response_text.lower():
                    return p
    return None
