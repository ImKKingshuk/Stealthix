from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from stealthix.core.session import ScanSession
from stealthix.impact.models import (
    FILE_READ,
    FILE_WRITE,
    OS_COMMAND,
    UDF_DROPPER,
    AuditMetadata,
    ImpactOperation,
    OperationPlan,
    OperationStep,
)
from stealthix.impact.profiles import get_capability, get_profile, normalize_dbms, profiles_as_dict


def build_capability_matrix() -> dict[str, Any]:
    return profiles_as_dict()


def plan_impact_operation(
    dbms: str | None,
    operation: ImpactOperation,
    *,
    parameters: Mapping[str, Any] | None = None,
    operator: str | None = None,
    target: str | None = None,
    reason: str | None = None,
    evidence: Mapping[str, Any] | None = None,
) -> OperationPlan:
    capability = get_capability(dbms, operation)
    profile = get_profile(dbms)
    label = profile.dbms if profile else str(dbms or "auto").strip().lower() or "auto"
    params = dict(parameters or {})
    warnings = _warnings_for(capability, params)
    return OperationPlan(
        dbms=label,
        operation=operation,
        capability=capability,
        parameters=params,
        steps=_steps_for(label, operation, capability.supported),
        audit=AuditMetadata(
            operator=operator,
            target=target,
            reason=reason,
            labels=("operator-controlled", "impact", operation),
            evidence=dict(evidence or {}),
        ),
        warnings=tuple(warnings),
        status="planned" if capability.supported else "unsupported",
    )


def _session_evidence(session: ScanSession | None) -> dict[str, Any]:
    if session is None:
        return {}
    evidence: dict[str, Any] = {}
    fingerprint = session.metadata.get("fingerprint")
    if isinstance(fingerprint, dict):
        evidence["fingerprint"] = {
            str(key): value
            for key, value in fingerprint.items()
            if key in {"dbms", "dbms_version", "os", "database"}
        }
    plugin = session.metadata.get("plugin")
    if isinstance(plugin, dict):
        evidence["plugin"] = {
            str(key): plugin[key]
            for key in ("name", "family", "dbms")
            if key in plugin and plugin[key]
        }
    return evidence


def _session_dbms(session: ScanSession | None, dbms: str | None) -> str | None:
    selected = dbms or (session.config.dbms if session is not None else None)
    return normalize_dbms(selected) or selected


def plan_operation(
    operation: ImpactOperation,
    *,
    session: ScanSession | None = None,
    dbms: str | None = None,
    parameters: Mapping[str, Any] | None = None,
    operator: str | None = None,
    reason: str | None = None,
    target: str | None = None,
    labels: tuple[str, ...] = (),
) -> OperationPlan:
    evidence = _session_evidence(session)
    if labels:
        evidence["labels"] = list(labels)
    return plan_impact_operation(
        _session_dbms(session, dbms),
        operation,
        parameters=parameters,
        operator=operator,
        target=target or (session.config.base_url if session is not None else None),
        reason=reason,
        evidence=evidence,
    )


def plan_file_read(
    session: ScanSession | None = None,
    path: str = "",
    *,
    dbms: str | None = None,
    operator: str | None = None,
    reason: str | None = None,
) -> OperationPlan:
    return plan_operation(
        FILE_READ,
        session=session,
        dbms=dbms,
        parameters={"path": path},
        operator=operator,
        reason=reason,
        labels=("file", "read"),
    )


def plan_file_write(
    session: ScanSession | None = None,
    path: str = "",
    content: str | bytes = "",
    *,
    dbms: str | None = None,
    operator: str | None = None,
    reason: str | None = None,
) -> OperationPlan:
    return plan_operation(
        FILE_WRITE,
        session=session,
        dbms=dbms,
        parameters={"path": path, "content": content},
        operator=operator,
        reason=reason,
        labels=("file", "write"),
    )


def plan_os_command(
    session: ScanSession | None = None,
    command: str = "",
    *,
    dbms: str | None = None,
    operator: str | None = None,
    reason: str | None = None,
) -> OperationPlan:
    return plan_operation(
        OS_COMMAND,
        session=session,
        dbms=dbms,
        parameters={"command": command},
        operator=operator,
        reason=reason,
        labels=("os", "command"),
    )


def plan_udf_dropper(
    session: ScanSession | None = None,
    *,
    dbms: str | None = None,
    operator: str | None = None,
    reason: str | None = None,
) -> OperationPlan:
    return plan_operation(
        UDF_DROPPER,
        session=session,
        dbms=dbms,
        parameters={},
        operator=operator,
        reason=reason,
        labels=("udf", "dropper", "feasibility"),
    )


def _warnings_for(capability: Any, parameters: Mapping[str, Any]) -> list[str]:
    warnings: list[str] = []
    if not capability.supported:
        warnings.append(capability.unsupported_reason or "Capability is unsupported for this DBMS.")
    if capability.destructive:
        warnings.append(
            "This operation can modify the target or host and requires explicit opt-in."
        )
    if capability.requires_stacked:
        warnings.append(
            "This operation usually requires stacked query support or an equivalent executor."
        )
    if capability.required_privileges:
        warnings.append(
            "Required privileges: "
            + ", ".join(str(item) for item in capability.required_privileges)
        )
    if capability.required_features:
        warnings.append(
            "Required features: " + ", ".join(str(item) for item in capability.required_features)
        )
    if not capability.execution_supported:
        warnings.append(
            "Stealthix models this as assessment/planning only; no built-in executor is enabled."
        )
    if capability.operation == FILE_READ and not parameters.get("path"):
        warnings.append("A file path is required before execution.")
    if capability.operation == FILE_WRITE:
        if not parameters.get("path"):
            warnings.append("A destination path is required before execution.")
        if not any(key in parameters for key in ("content", "data", "file_content")):
            warnings.append("File content is required before execution.")
    if capability.operation == OS_COMMAND and not parameters.get("command"):
        warnings.append("A command is required before execution.")
    return warnings


def _steps_for(dbms: str, operation: ImpactOperation, supported: bool) -> tuple[OperationStep, ...]:
    if not supported:
        return (
            OperationStep(
                name="select-supported-dbms",
                description=f"Fingerprint or choose a DBMS with a supported {operation} profile.",
                kind="precondition",
            ),
        )
    common = (
        OperationStep(
            name="confirm-authorization",
            description="Confirm this target and operation are explicitly authorized.",
            kind="operator_gate",
            requires_confirmation=True,
        ),
        OperationStep(
            name="capture-evidence-baseline",
            description="Record request, response, DBMS fingerprint, privilege, and timing evidence.",
            kind="evidence",
        ),
    )
    if operation == FILE_READ:
        return common + (
            OperationStep(
                name="attempt-file-read",
                description=f"Execute the {dbms} file-read primitive and capture response evidence.",
                kind="execution",
            ),
            OperationStep(
                name="verify-file-content",
                description="Validate that the response is content and not a DBMS error page.",
                kind="verification",
            ),
        )
    if operation == FILE_WRITE:
        return common + (
            OperationStep(
                name="attempt-file-write",
                description=f"Execute the {dbms} file-write primitive with explicit operator approval.",
                kind="execution",
                destructive=True,
                requires_confirmation=True,
            ),
            OperationStep(
                name="verify-write-impact",
                description="Verify write impact through an independent read or application-side proof.",
                kind="verification",
            ),
        )
    if operation == OS_COMMAND:
        return common + (
            OperationStep(
                name="execute-command",
                description=f"Execute the {dbms} OS-command primitive with explicit operator approval.",
                kind="execution",
                destructive=True,
                requires_confirmation=True,
            ),
            OperationStep(
                name="verify-command-output",
                description="Capture bounded stdout/stderr proof and command execution metadata.",
                kind="verification",
            ),
        )
    if operation == UDF_DROPPER:
        return common + (
            OperationStep(
                name="assess-native-extension-path",
                description="Assess plugin/library directory, architecture, privileges, and cleanup requirements.",
                kind="assessment",
                destructive=True,
                requires_confirmation=True,
            ),
        )
    raise ValueError(f"Unknown impact operation: {operation}")


__all__ = [
    "build_capability_matrix",
    "plan_file_read",
    "plan_file_write",
    "plan_impact_operation",
    "plan_operation",
    "plan_os_command",
    "plan_udf_dropper",
]
