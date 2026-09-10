from __future__ import annotations

from stealthix.plugins.base import Plugin

TIMESERIES_PLUGINS = [
    Plugin(
        "influxdb",
        "nosql",
        dbms="influxdb",
        payloads=['from() |> filter(fn: (r.field == "1"))', 'SELECT * WHERE field = "1"'],
        fingerprints=["influxdb", "flux", "influxql"],
        error_signatures=["influxdb", "flux", "influxql", "error"],
        version_queries=["from() |> limit(1) |> yield()", "SHOW DIAGNOSTICS"],
        privilege_checks=["SHOW USERS", "SHOW GRANTS"],
        os_queries=["SHOW DIAGNOSTICS"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["SHOW DATABASES", "SHOW BUCKETS"],
                "patterns": [r"\bbucket[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["SHOW MEASUREMENTS", "from() |> group()"],
                "patterns": [
                    r"\bmeasurement[:=\s]+([a-z0-9_\-]+)",
                    r"\btable[:=\s]+([a-z0-9_\-]+)",
                ],
            },
            "columns": {
                "payloads": ["SHOW FIELD KEYS", "SHOW TAG KEYS"],
                "patterns": [r"\bfield[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["SELECT * WHERE 1=1", "from() |> range(start: -1h)"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
    Plugin(
        "prometheus",
        "nosql",
        dbms="prometheus",
        payloads=['metric_name{label="1"}', 'metric_name{label="value"}'],
        fingerprints=["prometheus", "promql"],
        error_signatures=["prometheus", "promql", "parse error"],
        version_queries=["up", "prometheus_build_info"],
        privilege_checks=["up", "prometheus_build_info"],
        os_queries=["node_exporter_build_info"],
        preferred_techniques="BET",
        extraction_profiles={
            "databases": {
                "payloads": ["up", "prometheus_build_info"],
                "patterns": [r"\bjob[:=\s]+([a-z0-9_\-]+)", r"\bdatabase[:=\s]+([a-z0-9_\-]+)"],
            },
            "tables": {
                "payloads": ["up", 'count by (__name__) ({__name__=~".+"})'],
                "patterns": [r"\bmetric[:=\s]+([a-z0-9_\-:]+)", r"\btable[:=\s]+([a-z0-9_\-]+)"],
            },
            "columns": {
                "payloads": ["label_values(metric_name, label)", "up"],
                "patterns": [r"\blabel[:=\s]+([a-z0-9_\-]+)", r"\bcolumn[:=\s]+([a-z0-9_\-]+)"],
            },
            "dump": {
                "payloads": ["up", "metric_name"],
            },
            "files": {"disabled": True},
            "os": {"disabled": True},
        },
    ),
]

__all__ = ["TIMESERIES_PLUGINS"]
