from __future__ import annotations

from typing import Any

from stealthix._tui_runtime.constants import (
    SUPPORTED_DBMS,
    SUPPORTED_METHODS,
    SUPPORTED_REPORT_FORMATS,
)
from stealthix.plugins import all_plugins
from stealthix.plugins.base import Plugin
from stealthix.plugins.selector import get_plugin

_FAMILY_ORDER = {"sql": 0, "nosql": 1, "newsql": 2}
_TECHNIQUE_LABELS = {
    "B": "boolean",
    "E": "error",
    "U": "union",
    "T": "time",
    "S": "stacked",
}
_EXTRACTION_OPERATIONS = {
    "databases": "Enum DBs",
    "tables": "Enum Tables",
    "columns": "Enum Columns",
    "dump": "Dump",
    "files": "File Read",
    "os": "OS Cmd",
    "hashes": "Hashes",
}
_ALIASES = {
    "postgres": "postgresql",
    "cockroach": "cockroachdb",
    "yugabyte": "yugabytedb",
    "redshift": "redshift",
    "greenplum": "greenplum",
    "vertica": "vertica",
    "yellowbrick": "yellowbrick",
    "enterprisedb": "enterprisedb",
    "yugabyte_ysql": "yugabyte_ysql",
    "timescaledb": "timescaledb",
    "percona": "percona",
    "memsql": "memsql",
    "drizzle": "drizzle",
    "h2": "h2",
    "hsqldb": "hsqldb",
    "sybase": "sybase",
    "azure_synapse": "azure_synapse",
    "firebird": "firebird",
    "sap_maxdb": "sap_maxdb",
    "informix": "informix",
    "monetdb": "monetdb",
    "clickhouse": "clickhouse",
    "snowflake": "snowflake",
    "bigquery": "bigquery",
    "apache_derby": "apache_derby",
    "presto": "presto",
    "trino": "trino",
    "duckdb": "duckdb",
    "cubrid": "cubrid",
    "altibase": "altibase",
    "mimersql": "mimersql",
    "cratedb": "cratedb",
    "mckoi": "mckoi",
    "cache": "cache",
    "virtuoso": "virtuoso",
    "frontbase": "frontbase",
    "raima": "raima",
    "extremedb": "extremedb",
    "memsql": "singlestore",
    "voltdb": "voltdb",
    "nuodb": "nuodb",
    "oceanbase": "oceanbase",
    "polardb": "polardb",
    "tiflash": "tiflash",
    "ycql": "yugabyte_ycql",
    "arangodb": "arangodb",
    "couchbase": "couchbase",
    "rethinkdb": "rethinkdb",
    "orientdb": "orientdb",
    "neo4j": "neo4j",
    "janusgraph": "janusgraph",
    "neptune": "neptune",
    "elasticsearch": "elasticsearch",
    "solr": "solr",
    "opensearch": "opensearch",
    "influxdb": "influxdb",
    "prometheus": "prometheus",
    "aerospike": "aerospike",
    "riak": "riak",
    "cosmosdb": "cosmosdb",
    "documentdb": "documentdb",
}
_DNS_OOB_ENGINES = {
    "mysql",
    "mariadb",
    "mssql",
    "oracle",
    "postgresql",
    "cockroachdb",
    "tidb",
    "yugabytedb",
    "redshift",
    "greenplum",
    "vertica",
    "yellowbrick",
    "enterprisedb",
    "yugabyte_ysql",
    "timescaledb",
    "percona",
    "memsql",
    "drizzle",
    "h2",
    "hsqldb",
    "sybase",
    "azure_synapse",
    "db2",
    "firebird",
    "sap_maxdb",
    "informix",
    "monetdb",
    "clickhouse",
    "snowflake",
    "presto",
    "trino",
    "duckdb",
    "cubrid",
    "altibase",
    "mimersql",
    "cratedb",
}
_BLIND_EXTRACTION_ENGINES = {
    "mysql",
    "mariadb",
    "mssql",
    "oracle",
    "postgresql",
    "cockroachdb",
    "sqlite",
    "tidb",
    "yugabytedb",
    "redshift",
    "greenplum",
    "vertica",
    "yellowbrick",
    "enterprisedb",
    "yugabyte_ysql",
    "timescaledb",
    "percona",
    "memsql",
    "drizzle",
    "h2",
    "hsqldb",
    "sybase",
    "azure_synapse",
    "db2",
    "firebird",
    "sap_maxdb",
    "informix",
    "monetdb",
    "clickhouse",
    "snowflake",
    "bigquery",
    "apache_derby",
    "presto",
    "trino",
    "duckdb",
    "cubrid",
    "altibase",
    "mimersql",
    "cratedb",
    "mckoi",
    "cache",
    "virtuoso",
    "frontbase",
    "raima",
    "extremedb",
    "voltdb",
    "nuodb",
    "singlestore",
    "oceanbase",
    "polardb",
    "tiflash",
    "spanner",
}
_NOSQL_EXTRACTION_ENGINES = {
    "mongodb",
    "couchdb",
    "redis",
    "cassandra",
    "dynamodb",
    "firebase",
    "arangodb",
    "couchbase",
    "rethinkdb",
    "orientdb",
    "neo4j",
    "janusgraph",
    "neptune",
    "elasticsearch",
    "solr",
    "opensearch",
    "influxdb",
    "prometheus",
    "aerospike",
    "riak",
    "cosmosdb",
    "documentdb",
    "yugabyte_ycql",
}
_PLATFORM_CONFIDENCE = [
    {
        "platform": "macos",
        "confidence": "strong",
        "release_artifacts": ["wheel:x86_64", "wheel:aarch64"],
        "notes": "Covered by the release workflow and current install guidance.",
    },
    {
        "platform": "linux",
        "confidence": "strong",
        "release_artifacts": ["wheel:x86_64", "wheel:aarch64"],
        "notes": "Covered by the release workflow and current install guidance.",
    },
    {
        "platform": "windows",
        "confidence": "moderate",
        "release_artifacts": ["wheel:x86_64"],
        "notes": "The workflow now targets native Windows MSVC wheels, but live release/install evidence is still thinner than macOS/Linux, so WSL or source installs remain safe fallbacks.",
    },
]
_RUNTIME_CAPABILITIES = {
    "oob": [
        {
            "name": "dns_callbacks",
            "status": "partial",
            "activation": "env-gated",
            "notes": "SQLi OOB helper now supports plugin-aware DNS callback templates and can optionally confirm tokens through the local DNS listener.",
        },
        {
            "name": "listener_query_log",
            "status": "implemented",
            "activation": "env-gated",
            "notes": "The local DNS listener now exposes observed query logs and multi-token confirmation for richer OOB evidence capture.",
        },
    ],
    "waf": [
        {
            "name": "auto_detection",
            "status": "heuristic",
            "notes": "Header/body signatures plus optional Rust-side WAF detector populate session metadata.",
        },
        {
            "name": "cloudflare_bypass",
            "status": "implemented",
            "notes": "Rust bypass helper can be selected explicitly or via detected WAF metadata.",
        },
        {
            "name": "modsecurity_bypass",
            "status": "implemented",
            "notes": "Rust bypass helper is available through the shared payload-bypass path.",
        },
        {
            "name": "generic_payload_obfuscation",
            "status": "implemented",
            "notes": "Fallback Rust obfuscation can be applied when a specific WAF helper is not available.",
        },
        {
            "name": "adaptive_request_retries",
            "status": "implemented",
            "notes": "The shared Python HTTP path can retry transient or WAF-blocked responses with Retry-After/backoff handling, hostile-target metadata capture, and adaptive tamper escalation.",
        },
        {
            "name": "adaptive_tamper_pipeline",
            "status": "implemented",
            "activation": "opt-in-or-auto",
            "notes": "WAF fingerprints can now select vendor-aware payload tamper chains, while operators can override or extend the sequence with explicit tamper scripts.",
        },
        {
            "name": "request_fragmentation",
            "status": "implemented",
            "activation": "adaptive-retry",
            "notes": "Blocked requests can fall back to a fragmented Python HTTP transport that splits the serialized request body across multiple socket writes.",
        },
        {
            "name": "parameter_pollution_and_entity_bypass",
            "status": "implemented",
            "activation": "adaptive-retry",
            "notes": "Adaptive retries can duplicate query/form parameters and switch to JSON/XML-friendly entity encodings when the initial payload is blocked.",
        },
    ],
    "api": [
        {
            "name": "schema_import",
            "status": "implemented",
            "activation": "opt-in",
            "notes": "OpenAPI/Swagger and Postman collections can be imported into multi-target REST scans with path/query/header/body parameter metadata.",
        },
        {
            "name": "content_type_aware_param_discovery",
            "status": "implemented",
            "activation": "always-on",
            "notes": "Path, query, header, JSON, XML, form, and multipart-style API parameters are surfaced through the shared targeting layer.",
        },
    ],
    "websocket": [
        {
            "name": "message_mutation",
            "status": "implemented",
            "activation": "opt-in",
            "notes": "WebSocket scans can mutate baseline messages and evaluate reflected or error-driven responses.",
        },
        {
            "name": "timing_probes",
            "status": "heuristic",
            "activation": "opt-in",
            "notes": "WebSocket scans perform blind timing probes against mutated messages to flag potential delayed-execution behavior.",
        },
    ],
    "automation": [
        {
            "name": "checkpoint_resume",
            "status": "implemented",
            "activation": "opt-in",
            "notes": "Headless scan flows can persist resumable checkpoints with findings, queue/progress state, and session context, then resume from the saved artifact later.",
        },
        {
            "name": "atomic_checkpoint_writes",
            "status": "implemented",
            "activation": "always-on",
            "notes": "Checkpoint files are written atomically through temp-file replacement so interrupted saves do not leave a partially-written scan state behind.",
        },
        {
            "name": "ci_exit_code_semantics",
            "status": "implemented",
            "activation": "always-on",
            "notes": "Headless scan commands use CI-friendly exit codes: 0 for clean runs, 1 for completed runs with findings, and 2 for operational failures.",
        },
        {
            "name": "ci_templates",
            "status": "implemented",
            "activation": "docs-and-templates",
            "notes": "Repository templates now cover GitHub Actions SARIF uploads and GitLab JSON artifact flows, including resumable checkpoint wiring for long-running scans.",
        },
    ],
}
_VALIDATION_METADATA = {
    "ci_workflows": [
        "pre-release-checks",
        "release-publishing",
        "workflow-template:stealthix-headless-scan",
        "gitlab-template:gitlab-stealthix",
    ],
    "recommended_local_checks": [
        "uv run pytest -q",
        "uv run cargo fmt --check",
        "uv run cargo test --workspace --quiet",
        "uv run python -m stealthix --cli support --format json",
    ],
    "support_depth_labels": {
        "rich": "DBMS-specific extraction profiles exist for multiple workflows and are covered by focused unit/integration checks.",
        "moderate": "Explicit DBMS-aware logic exists, but proof depth is metadata-only, heuristic, or narrower.",
        "detection-focused": "Detection/fingerprinting exists, but extraction depth is intentionally narrow.",
    },
    "proof_tier_labels": {
        "profile-unit-tested": "Extraction profile metadata is exercised by focused unit or integration tests.",
        "profile-metadata": "Extraction profile metadata exists, but no focused proof fixture is declared here.",
        "heuristic": "Support is inferred from shared heuristic extraction paths.",
        "fingerprint": "Detection or fingerprinting metadata exists without extraction proof.",
        "declared": "The plugin is declared, but proof metadata is intentionally minimal.",
    },
}
_PROFILE_UNIT_TESTED_ENGINES = {
    "mysql",
    "mssql",
    "sqlite",
    "oracle",
    "db2",
    "mongodb",
    "cockroachdb",
    "tidb",
    "yugabytedb",
}


def _normalize_dbms_name(dbms: str | None) -> str | None:
    if not dbms:
        return None
    lowered = dbms.strip().lower()
    return _ALIASES.get(lowered, lowered)


def _plugin_order(plugin: Plugin) -> tuple[int, str]:
    return (_FAMILY_ORDER.get(plugin.family, 99), plugin.name)


def _profile_supported(plugin: Plugin, operation: str) -> bool:
    profile = plugin.extraction_profiles.get(operation)
    if not isinstance(profile, dict) or profile.get("disabled"):
        return False
    return bool(profile.get("payloads") or profile.get("patterns"))


def _hash_support_state(plugin: Plugin) -> str:
    return "heuristic" if plugin.family in {"sql", "newsql"} else "unsupported"


def _oob_state(plugin: Plugin) -> str:
    return "partial" if plugin.name in _DNS_OOB_ENGINES else "unsupported"


def _extraction_counts(plugin: Plugin) -> tuple[int, int]:
    supported_extraction = sum(
        1
        for operation in ("databases", "tables", "columns", "dump", "files", "os")
        if _profile_supported(plugin, operation)
    )
    heuristic_extraction = sum(
        1
        for operation in ("databases", "tables", "columns", "dump", "files", "os")
        if _extraction_state(plugin, operation) == "heuristic"
    )
    return supported_extraction, heuristic_extraction


def _fixture_status(plugin: Plugin) -> str:
    if plugin.name in _PROFILE_UNIT_TESTED_ENGINES:
        return "unit-tested"
    return "metadata-only"


def _proof_tier(plugin: Plugin) -> str:
    supported_extraction, heuristic_extraction = _extraction_counts(plugin)
    if supported_extraction >= 1:
        if _fixture_status(plugin) == "unit-tested":
            return "profile-unit-tested"
        return "profile-metadata"
    if heuristic_extraction >= 1:
        return "heuristic"
    if plugin.fingerprints or plugin.error_signatures or plugin.version_queries:
        return "fingerprint"
    return "declared"


def _support_depth(plugin: Plugin) -> str:
    supported_extraction, heuristic_extraction = _extraction_counts(plugin)
    proof_tier = _proof_tier(plugin)
    if supported_extraction >= 4 and proof_tier == "profile-unit-tested":
        return "rich"
    if (
        supported_extraction + heuristic_extraction >= 1
        or plugin.version_queries
        or plugin.privilege_checks
    ):
        return "moderate"
    return "detection-focused"


def _extraction_state(plugin: Plugin, operation: str) -> str:
    if operation == "hashes":
        return _hash_support_state(plugin)
    if _profile_supported(plugin, operation):
        return "supported"
    if operation in {"databases", "tables", "columns", "dump"}:
        if plugin.name in _BLIND_EXTRACTION_ENGINES:
            return "heuristic"
        if plugin.name in _NOSQL_EXTRACTION_ENGINES:
            return "heuristic"
    return "unsupported"


def _techniques(plugin: Plugin) -> list[str]:
    raw = plugin.preferred_techniques or ""
    return [_TECHNIQUE_LABELS[ch] for ch in raw if ch in _TECHNIQUE_LABELS]


def _notes(plugin: Plugin) -> str:
    notes: list[str] = []
    supported_extraction = [
        operation
        for operation in ("databases", "tables", "columns", "dump", "files", "os")
        if _extraction_state(plugin, operation) == "supported"
    ]
    if supported_extraction:
        notes.append("DBMS-specific extraction profile")
        if _proof_tier(plugin) == "profile-metadata":
            notes.append("profile proof is metadata-only")
    else:
        notes.append("detection-focused profile")
    if not plugin.version_queries:
        notes.append("limited version fingerprint helpers")
    if plugin.name in _NOSQL_EXTRACTION_ENGINES:
        notes.append("heuristic NoSQL extraction helpers available")
    elif plugin.family == "nosql":
        notes.append("NoSQL extraction coverage is intentionally narrow")
    if plugin.name in _BLIND_EXTRACTION_ENGINES and not supported_extraction:
        notes.append("blind extraction fallback available")
    if plugin.family == "newsql" and not plugin.extraction_profiles:
        notes.append("SQL-like detection with heuristic extraction")
    if _oob_state(plugin) == "partial":
        notes.append("DNS-oriented OOB helper exists")
    return "; ".join(notes)


def build_support_matrix() -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for plugin in sorted(all_plugins(), key=_plugin_order):
        rows.append(
            {
                "name": plugin.name,
                "family": plugin.family,
                "techniques": _techniques(plugin),
                "fingerprinting": bool(plugin.fingerprints or plugin.error_signatures),
                "version_queries": bool(plugin.version_queries),
                "privilege_checks": bool(plugin.privilege_checks),
                "os_fingerprinting": bool(plugin.os_queries),
                "support_depth": _support_depth(plugin),
                "proof_tier": _proof_tier(plugin),
                "fixture_status": _fixture_status(plugin),
                "oob": {"dns_callbacks": _oob_state(plugin)},
                "extraction": {
                    operation: _extraction_state(plugin, operation)
                    for operation in _EXTRACTION_OPERATIONS
                },
                "notes": _notes(plugin),
            }
        )
    return {
        "dbms_selector_values": list(SUPPORTED_DBMS),
        "http_methods": list(SUPPORTED_METHODS),
        "report_formats": list(SUPPORTED_REPORT_FORMATS),
        "platform_confidence": list(_PLATFORM_CONFIDENCE),
        "runtime_capabilities": _RUNTIME_CAPABILITIES,
        "validation": _VALIDATION_METADATA,
        "dbms": rows,
    }


def get_support_entry(dbms: str | None) -> dict[str, Any] | None:
    normalized = _normalize_dbms_name(dbms)
    if not normalized or normalized == "auto":
        return None
    for entry in build_support_matrix()["dbms"]:
        if entry["name"] == normalized:
            return entry
    plugin = get_plugin(normalized)
    if plugin is None:
        return None
    return next(
        (entry for entry in build_support_matrix()["dbms"] if entry["name"] == plugin.name), None
    )


def ensure_extraction_supported(dbms: str | None, operation: str) -> None:
    label = _EXTRACTION_OPERATIONS.get(operation, operation)
    entry = get_support_entry(dbms)
    if entry is None:
        raise ValueError(
            f"{label} requires an explicit or detected DBMS with a supported profile. "
            "See `stealthix support` or `docs/support-matrix.md`."
        )
    state = entry["extraction"].get(operation)
    if state == "supported":
        return
    if state == "heuristic":
        return
    raise ValueError(
        f"{label} is not currently supported for DBMS '{entry['name']}'. "
        "See `stealthix support` or `docs/support-matrix.md`."
    )


def _state_cell(state: str) -> str:
    if state == "supported":
        return "✅"
    if state == "partial":
        return "◐"
    if state == "heuristic":
        return "🔬"
    return "—"


def render_support_matrix_markdown(matrix: dict[str, Any] | None = None) -> str:
    matrix = build_support_matrix() if matrix is None else matrix
    capability_lines: list[str] = []
    for family, items in matrix["runtime_capabilities"].items():
        for item in items:
            capability_lines.append(
                f"- `{family}.{item['name']}` — **{item['status']}** ({item.get('activation', 'always-on')}) — {item['notes']}"
            )
    lines = [
        "# Support Matrix",
        "",
        "> This document is derived from the runtime capability metadata in `stealthix/support_matrix.py`.",
        "",
        "## Global capabilities",
        "",
        f"- Supported DBMS selector values: `{', '.join(matrix['dbms_selector_values'])}`",
        f"- Supported HTTP methods: `{', '.join(matrix['http_methods'])}`",
        f"- Supported report formats: `{', '.join(matrix['report_formats'])}`",
        "",
        "## Runtime capability notes",
        "",
        *capability_lines,
        "",
        "## Validation and release confidence",
        "",
        f"- CI workflows: `{', '.join(matrix['validation']['ci_workflows'])}`",
        f"- Recommended local checks: `{', '.join(matrix['validation']['recommended_local_checks'])}`",
        "",
        "| Platform | Confidence | Release Artifacts | Notes |",
        "| --- | --- | --- | --- |",
    ]
    for entry in matrix["platform_confidence"]:
        artifacts = ", ".join(entry["release_artifacts"]) or "none currently published"
        lines.append(
            f"| {entry['platform']} | {entry['confidence']} | {artifacts} | {entry['notes'].replace('|', '/')} |"
        )
    lines.extend(
        [
            "",
            "## DBMS capabilities",
            "",
            "| DBMS | Family | Support Depth | Proof Tier | Fixture Status | Techniques | Enum DBs | Enum Tables | Enum Columns | Dump | File Read | OS Cmd | Hashes | DNS OOB | Notes |",
            "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        ]
    )
    for entry in matrix["dbms"]:
        techniques = ", ".join(entry["techniques"]) or "n/a"
        extraction = entry["extraction"]
        lines.append(
            "| {name} | {family} | {support_depth} | {proof_tier} | {fixture_status} | {techniques} | {databases} | {tables} | {columns} | {dump} | {files} | {os} | {hashes} | {oob} | {notes} |".format(
                name=entry["name"],
                family=entry["family"],
                support_depth=entry["support_depth"],
                proof_tier=entry["proof_tier"],
                fixture_status=entry["fixture_status"],
                techniques=techniques,
                databases=_state_cell(extraction["databases"]),
                tables=_state_cell(extraction["tables"]),
                columns=_state_cell(extraction["columns"]),
                dump=_state_cell(extraction["dump"]),
                files=_state_cell(extraction["files"]),
                os=_state_cell(extraction["os"]),
                hashes=_state_cell(extraction["hashes"]),
                oob=_state_cell(entry["oob"]["dns_callbacks"]),
                notes=entry["notes"].replace("|", "/"),
            )
        )
    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "- `✅` — implemented with a DBMS-specific support profile in the current codebase",
            "- `◐` — implemented in a bounded or environment-gated form, but still intentionally limited in scope",
            "- `🔬` — available heuristically, but not backed by a DBMS-specific extraction profile",
            "- `—` — not currently implemented as a supported workflow for that DBMS",
            "- Support depth `rich` / `moderate` / `detection-focused` is proof-aware. Metadata-only profiles are not promoted to `rich` unless focused tests exercise the profile path.",
            "",
            "Current repo-verified release/install confidence is strongest on **macOS** and **Linux**. The workflow now targets a native **Windows x86_64** wheel as well, but Windows evidence is still thinner overall, so **WSL or source-based workflows** remain safe fallbacks if native installs hit issues.",
        ]
    )
    return "\n".join(lines) + "\n"


def render_support_matrix_text(matrix: dict[str, Any] | None = None) -> str:
    matrix = build_support_matrix() if matrix is None else matrix
    lines = [
        "Stealthix support matrix",
        f"DBMS selector values: {', '.join(matrix['dbms_selector_values'])}",
        f"HTTP methods: {', '.join(matrix['http_methods'])}",
        f"Report formats: {', '.join(matrix['report_formats'])}",
        f"CI workflows: {', '.join(matrix['validation']['ci_workflows'])}",
        "",
        "Runtime capabilities:",
    ]
    for family, items in matrix["runtime_capabilities"].items():
        for item in items:
            lines.append(
                f"- {family}.{item['name']} status={item['status']} activation={item.get('activation', 'always-on')}"
            )
    lines.append("")
    lines.append("Platform confidence:")
    for entry in matrix["platform_confidence"]:
        artifacts = ",".join(entry["release_artifacts"]) or "none"
        lines.append(
            f"- {entry['platform']} confidence={entry['confidence']} artifacts={artifacts}"
        )
    lines.append("")
    for entry in matrix["dbms"]:
        extraction = entry["extraction"]
        lines.append(
            f"- {entry['name']} [{entry['family']}] support_depth={entry['support_depth']} proof_tier={entry['proof_tier']} fixture_status={entry['fixture_status']} techniques={','.join(entry['techniques']) or 'n/a'} "
            f"enum_dbs={extraction['databases']} enum_tables={extraction['tables']} "
            f"enum_columns={extraction['columns']} dump={extraction['dump']} "
            f"file_read={extraction['files']} os_cmd={extraction['os']} hashes={extraction['hashes']} oob_dns={entry['oob']['dns_callbacks']}"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "build_support_matrix",
    "ensure_extraction_supported",
    "get_support_entry",
    "render_support_matrix_markdown",
    "render_support_matrix_text",
]
