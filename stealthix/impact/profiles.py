from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from stealthix.impact.models import (
    FILE_READ,
    FILE_WRITE,
    OS_COMMAND,
    UDF_DROPPER,
    Capability,
    CapabilityProfile,
    ImpactOperation,
)


def _cap(
    operation: ImpactOperation,
    *,
    supported: bool,
    summary: str,
    primitives: Iterable[str] = (),
    requires_stacked: bool = False,
    required_privileges: Iterable[str] = (),
    required_features: Iterable[str] = (),
    execution_supported: bool = True,
    destructive: bool = False,
    unsupported_reason: str | None = None,
    evidence_hints: Iterable[str] = (),
    notes: Iterable[str] = (),
) -> Capability:
    return Capability(
        operation=operation,
        supported=supported,
        summary=summary,
        primitives=tuple(primitives),
        requires_stacked=requires_stacked,
        required_privileges=tuple(required_privileges),
        required_features=tuple(required_features),
        execution_supported=execution_supported,
        destructive=destructive,
        unsupported_reason=unsupported_reason,
        evidence_hints=tuple(evidence_hints),
        notes=tuple(notes),
    )


def _unsupported(operation: ImpactOperation, dbms: str, reason: str) -> Capability:
    return _cap(
        operation,
        supported=False,
        summary=f"{dbms} {operation} is unsupported by the impact layer.",
        execution_supported=False,
        unsupported_reason=reason,
    )


PROFILES: dict[str, CapabilityProfile] = {
    "mysql": CapabilityProfile(
        dbms="mysql",
        family="sql",
        aliases=("percona",),
        notes=("MariaDB has a separate profile because UDF and plugin path behavior can differ.",),
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="Server-side file read is feasible through MySQL file functions.",
                primitives=("LOAD_FILE",),
                required_privileges=("FILE",),
                required_features=("secure_file_priv permits the requested path",),
                evidence_hints=("current_user", "@@secure_file_priv", "FILE privilege check"),
                notes=(
                    "Returns NULL when the DBMS account, path, or secure_file_priv policy blocks access.",
                ),
            ),
            FILE_WRITE: _cap(
                FILE_WRITE,
                supported=True,
                summary="Server-side file write is feasible through outfile-style primitives.",
                primitives=("SELECT INTO OUTFILE", "SELECT INTO DUMPFILE"),
                required_privileges=("FILE",),
                required_features=(
                    "secure_file_priv permits destination",
                    "target file does not already exist",
                ),
                destructive=True,
                evidence_hints=("@@secure_file_priv", "FILE privilege check"),
                notes=(
                    "The planner treats writes as modification operations and requires explicit execution opt-in.",
                ),
            ),
            OS_COMMAND: _cap(
                OS_COMMAND,
                supported=False,
                summary="MySQL has no built-in general OS command primitive.",
                execution_supported=False,
                unsupported_reason=(
                    "Direct OS command execution requires an additional unsafe chain such as a native UDF; "
                    "this layer models that only as UDF/dropper feasibility."
                ),
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="Native UDF deployment may be feasible but is assessment-only in this layer.",
                primitives=("UDF shared library in plugin_dir",),
                requires_stacked=True,
                required_privileges=(
                    "FILE",
                    "write access to plugin_dir or effective library path",
                ),
                required_features=("architecture-matched shared object", "plugin loading enabled"),
                execution_supported=False,
                destructive=True,
                evidence_hints=("@@plugin_dir", "@@secure_file_priv", "current_user"),
                notes=(
                    "No binary generation, upload, CREATE FUNCTION, or DROP FUNCTION is executed by Stealthix.",
                ),
            ),
        },
    ),
    "mariadb": CapabilityProfile(
        dbms="mariadb",
        family="sql",
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="Server-side file read is feasible through MariaDB file functions.",
                primitives=("LOAD_FILE",),
                required_privileges=("FILE",),
                required_features=("secure_file_priv permits the requested path",),
                evidence_hints=("current_user", "@@secure_file_priv", "FILE privilege check"),
            ),
            FILE_WRITE: _cap(
                FILE_WRITE,
                supported=True,
                summary="Server-side file write is feasible through outfile-style primitives.",
                primitives=("SELECT INTO OUTFILE", "SELECT INTO DUMPFILE"),
                required_privileges=("FILE",),
                required_features=(
                    "secure_file_priv permits destination",
                    "target file does not already exist",
                ),
                destructive=True,
                evidence_hints=("@@secure_file_priv", "FILE privilege check"),
            ),
            OS_COMMAND: _unsupported(
                OS_COMMAND,
                "MariaDB",
                "No built-in general OS command primitive; use UDF feasibility assessment only.",
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="Native UDF deployment may be feasible but is assessment-only in this layer.",
                primitives=("UDF shared library in plugin_dir",),
                requires_stacked=True,
                required_privileges=("FILE", "plugin_dir write path"),
                required_features=("architecture-matched shared object", "plugin loading enabled"),
                execution_supported=False,
                destructive=True,
                evidence_hints=("@@plugin_dir", "@@secure_file_priv", "current_user"),
            ),
        },
    ),
    "postgresql": CapabilityProfile(
        dbms="postgresql",
        family="sql",
        aliases=("postgres",),
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="Server-side file read is feasible through PostgreSQL administrative file functions.",
                primitives=("pg_read_file", "pg_read_binary_file"),
                required_privileges=("superuser", "pg_read_server_files"),
                required_features=("path accessible to database server process",),
                evidence_hints=("current_user", "role membership for pg_read_server_files"),
            ),
            FILE_WRITE: _cap(
                FILE_WRITE,
                supported=True,
                summary="Server-side file write is feasible through PostgreSQL administrative file functions.",
                primitives=("pg_write_file", "large object export"),
                requires_stacked=True,
                required_privileges=("superuser", "pg_write_server_files"),
                required_features=("path accessible to database server process",),
                destructive=True,
                evidence_hints=("current_user", "role membership for pg_write_server_files"),
            ),
            OS_COMMAND: _cap(
                OS_COMMAND,
                supported=True,
                summary="OS command execution is feasible only through privileged administrative COPY PROGRAM paths.",
                primitives=("COPY PROGRAM",),
                requires_stacked=True,
                required_privileges=("superuser", "pg_execute_server_program"),
                required_features=("COPY PROGRAM available",),
                destructive=True,
                evidence_hints=("current_user", "role membership for pg_execute_server_program"),
                notes=(
                    "The bundled session executor does not emit COPY PROGRAM payloads without an operator executor.",
                ),
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="Native extension/UDF deployment is theoretically feasible but assessment-only.",
                primitives=("CREATE FUNCTION ... LANGUAGE C", "CREATE EXTENSION"),
                requires_stacked=True,
                required_privileges=("superuser",),
                required_features=(
                    "server-side library deployment path",
                    "trusted extension controls allow it",
                ),
                execution_supported=False,
                destructive=True,
                evidence_hints=("current_user", "server_version", "shared_preload_libraries"),
            ),
        },
    ),
    "mssql": CapabilityProfile(
        dbms="mssql",
        family="sql",
        aliases=("sqlserver", "sql_server", "microsoft sql server"),
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="Server-side file read is feasible through bulk rowset primitives when enabled.",
                primitives=("OPENROWSET BULK",),
                required_privileges=("ADMINISTER BULK OPERATIONS", "bulkadmin or equivalent"),
                required_features=(
                    "Ad Hoc Distributed Queries enabled",
                    "server service account can read path",
                ),
                evidence_hints=("SYSTEM_USER", "IS_SRVROLEMEMBER('bulkadmin')"),
            ),
            FILE_WRITE: _unsupported(
                FILE_WRITE,
                "MSSQL",
                "Pure SQL arbitrary server-side file write is not exposed as a safe generic primitive; common paths route through OS command facilities.",
            ),
            OS_COMMAND: _cap(
                OS_COMMAND,
                supported=True,
                summary="OS command execution is feasible through xp_cmdshell when explicitly enabled.",
                primitives=("xp_cmdshell",),
                requires_stacked=True,
                required_privileges=("sysadmin",),
                required_features=("xp_cmdshell enabled",),
                destructive=True,
                evidence_hints=(
                    "SYSTEM_USER",
                    "IS_SRVROLEMEMBER('sysadmin')",
                    "xp_cmdshell enabled state",
                ),
            ),
            UDF_DROPPER: _unsupported(
                UDF_DROPPER,
                "MSSQL",
                "MSSQL impact routes are xp_cmdshell, Agent, OLE, or CLR-specific; native UDF dropper deployment is not modeled.",
            ),
        },
    ),
    "oracle": CapabilityProfile(
        dbms="oracle",
        family="sql",
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="File read can be feasible through UTL_FILE with a granted directory object.",
                primitives=("UTL_FILE", "DBMS_LOB via directory objects"),
                requires_stacked=True,
                required_privileges=("READ on DIRECTORY object",),
                required_features=("pre-existing DIRECTORY object mapped to target path",),
                evidence_hints=("USER", "ALL_DIRECTORIES", "directory object privileges"),
                notes=(
                    "Arbitrary path access is unsupported without a suitable directory object.",
                ),
            ),
            FILE_WRITE: _cap(
                FILE_WRITE,
                supported=True,
                summary="File write can be feasible through UTL_FILE with a granted directory object.",
                primitives=("UTL_FILE"),
                requires_stacked=True,
                required_privileges=("WRITE on DIRECTORY object",),
                required_features=("pre-existing DIRECTORY object mapped to destination path",),
                destructive=True,
                evidence_hints=("USER", "ALL_DIRECTORIES", "directory object privileges"),
            ),
            OS_COMMAND: _cap(
                OS_COMMAND,
                supported=True,
                summary="OS command execution is feasible only through highly privileged scheduler or Java paths.",
                primitives=("DBMS_SCHEDULER external job", "Java stored procedure"),
                requires_stacked=True,
                required_privileges=(
                    "CREATE JOB",
                    "CREATE EXTERNAL JOB",
                    "Java permissions or DBA-level grants",
                ),
                required_features=("external job execution configured",),
                execution_supported=False,
                destructive=True,
                evidence_hints=("USER", "role grants", "scheduler privileges"),
                notes=(
                    "The layer records feasibility but does not execute Oracle OS command paths.",
                ),
            ),
            UDF_DROPPER: _unsupported(
                UDF_DROPPER,
                "Oracle",
                "Oracle native library/extproc deployment is environment-specific DBA work, not a supported generic UDF dropper workflow.",
            ),
        },
    ),
    "sqlite": CapabilityProfile(
        dbms="sqlite",
        family="sql",
        capabilities={
            FILE_READ: _unsupported(
                FILE_READ,
                "SQLite",
                "SQLite SQL injection cannot safely expose arbitrary host file reads through a generic DBMS primitive.",
            ),
            FILE_WRITE: _unsupported(
                FILE_WRITE,
                "SQLite",
                "ATTACH can create database files, but arbitrary safe server-side file write is not modeled.",
            ),
            OS_COMMAND: _unsupported(
                OS_COMMAND,
                "SQLite",
                "No built-in OS command execution primitive is available through standard SQLite SQL.",
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="Extension loading can be feasible only for direct DB handles with extension loading enabled.",
                primitives=("load_extension",),
                required_privileges=("direct database connection controls",),
                required_features=(
                    "extension loading enabled by host process",
                    "extension path already present",
                ),
                execution_supported=False,
                destructive=True,
                unsupported_reason=None,
                notes=("Not considered a generic remote SQL injection impact path.",),
            ),
        },
    ),
    "db2": CapabilityProfile(
        dbms="db2",
        family="sql",
        aliases=("ibm_db2",),
        capabilities={
            FILE_READ: _unsupported(
                FILE_READ,
                "DB2",
                "DB2 has administrative import/export and routine mechanisms, but no safe generic arbitrary file read primitive is exposed here.",
            ),
            FILE_WRITE: _unsupported(
                FILE_WRITE,
                "DB2",
                "DB2 file writes are administrative/export paths with environment-specific side effects and are not modeled for execution.",
            ),
            OS_COMMAND: _unsupported(
                OS_COMMAND,
                "DB2",
                "OS command paths rely on external routines or administrative procedures requiring high privilege and are not safely generic.",
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="External UDF/routine deployment can be feasible for privileged administrators, assessment-only.",
                primitives=("external routine", "fenced UDF library"),
                requires_stacked=True,
                required_privileges=(
                    "DBADM or equivalent routine creation privileges",
                    "filesystem deployment path",
                ),
                required_features=(
                    "compatible library already deployed or administrator-controlled path"
                ),
                execution_supported=False,
                destructive=True,
                evidence_hints=("CURRENT USER", "routine privileges", "server platform"),
            ),
        },
    ),
    "clickhouse": CapabilityProfile(
        dbms="clickhouse",
        family="sql",
        capabilities={
            FILE_READ: _cap(
                FILE_READ,
                supported=True,
                summary="File read is limited to ClickHouse file table functions and configured user file paths.",
                primitives=("file table function",),
                required_privileges=("file table function permission",),
                required_features=("user_files_path or allowed path policy permits target"),
                evidence_hints=("currentUser", "server settings for file table functions"),
            ),
            FILE_WRITE: _unsupported(
                FILE_WRITE,
                "ClickHouse",
                "Server-side arbitrary file write is not modeled; INTO OUTFILE is client-side in common deployments.",
            ),
            OS_COMMAND: _unsupported(
                OS_COMMAND,
                "ClickHouse",
                "Executable UDFs are configuration-level server features, not generic SQL impact operations.",
            ),
            UDF_DROPPER: _cap(
                UDF_DROPPER,
                supported=True,
                summary="Executable UDF use may be feasible only when preconfigured by an administrator.",
                primitives=("executable user-defined function",),
                required_privileges=("administrator-controlled server config",),
                required_features=("preconfigured executable UDF XML/YAML entry",),
                execution_supported=False,
                destructive=True,
                evidence_hints=("system.functions", "server settings"),
                notes=("No UDF files or server config are written by Stealthix.",),
            ),
        },
    ),
    "trino": CapabilityProfile(
        dbms="trino",
        family="sql",
        aliases=("presto", "prestosql", "presto_db"),
        capabilities={
            FILE_READ: _unsupported(
                FILE_READ,
                "Trino/Presto",
                "Queries read data through connectors, not arbitrary coordinator or worker filesystem paths.",
            ),
            FILE_WRITE: _unsupported(
                FILE_WRITE,
                "Trino/Presto",
                "Writes are connector-mediated data writes, not arbitrary server filesystem writes.",
            ),
            OS_COMMAND: _unsupported(
                OS_COMMAND,
                "Trino/Presto",
                "No built-in OS command primitive is exposed through Trino/Presto SQL.",
            ),
            UDF_DROPPER: _unsupported(
                UDF_DROPPER,
                "Trino/Presto",
                "Function/plugin deployment is an administrator-side service deployment, not a SQL-level dropper path.",
            ),
        },
    ),
}


ALIASES: dict[str, str] = {}
for _name, _profile in PROFILES.items():
    ALIASES[_name] = _name
    for _alias in _profile.aliases:
        ALIASES[_alias] = _name
ALIASES["presto"] = "trino"


def normalize_dbms(dbms: str | None) -> str | None:
    if not dbms:
        return None
    normalized = dbms.strip().lower().replace(" ", "_")
    return ALIASES.get(normalized, normalized)


def get_profile(dbms: str | None) -> CapabilityProfile | None:
    normalized = normalize_dbms(dbms)
    if not normalized:
        return None
    return PROFILES.get(normalized)


def get_capability(dbms: str | None, operation: ImpactOperation) -> Capability:
    profile = get_profile(dbms)
    if profile is None:
        label = dbms or "auto"
        return Capability(
            operation=operation,
            supported=False,
            summary=f"No DBMS impact profile is available for '{label}'.",
            execution_supported=False,
            unsupported_reason="Select or fingerprint a DBMS with a declared impact profile first.",
        )
    return profile.capability(operation)


def profiles_as_dict() -> dict[str, Any]:
    return {name: profile.to_dict() for name, profile in PROFILES.items()}


__all__ = [
    "ALIASES",
    "PROFILES",
    "get_capability",
    "get_profile",
    "normalize_dbms",
    "profiles_as_dict",
]
