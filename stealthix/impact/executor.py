from __future__ import annotations

from collections.abc import Callable
from typing import Any, cast

from stealthix.core.session import ScanSession
from stealthix.extraction.files import read_file
from stealthix.extraction.os import execute_command
from stealthix.impact.models import (
    FILE_READ,
    FILE_WRITE,
    OS_COMMAND,
    UDF_DROPPER,
    ImpactExecutionOptions,
    ImpactExecutionResult,
    OperationPlan,
)

OperationRunner = Callable[[OperationPlan], dict[str, Any]]


class OperatorGateError(ValueError):
    pass


class SessionImpactExecutor:
    """Execute approved impact plans through existing extraction paths.

    File-write and UDF dropper operations require an injected runner because
    they are environment-specific and potentially destructive.
    """

    def __init__(
        self,
        session: ScanSession,
        *,
        file_write_runner: OperationRunner | None = None,
        udf_runner: OperationRunner | None = None,
    ) -> None:
        self.session = session
        self.file_write_runner = file_write_runner
        self.udf_runner = udf_runner

    def execute(
        self, plan: OperationPlan, options: ImpactExecutionOptions
    ) -> ImpactExecutionResult:
        blocked = _blocked_reason(plan, options)
        if blocked:
            return ImpactExecutionResult(
                plan=plan,
                executed=False,
                success=False,
                warnings=[*plan.warnings, blocked],
                error=blocked,
                audit=_audit(plan, options),
            )

        try:
            if plan.operation == FILE_READ:
                result = read_file(self.session, str(plan.parameters.get("path") or ""))
            elif plan.operation == OS_COMMAND:
                result = execute_command(self.session, str(plan.parameters.get("command") or ""))
            elif plan.operation == FILE_WRITE:
                if self.file_write_runner is None:
                    raise OperatorGateError("File-write execution requires an injected runner.")
                result = self.file_write_runner(plan)
            elif plan.operation == UDF_DROPPER:
                if self.udf_runner is None:
                    raise OperatorGateError("UDF/dropper execution requires an injected runner.")
                result = self.udf_runner(plan)
            else:
                raise OperatorGateError(f"Unsupported impact operation: {plan.operation}")
        except Exception as exc:
            return ImpactExecutionResult(
                plan=plan,
                executed=False,
                success=False,
                warnings=list(plan.warnings),
                error=f"{type(exc).__name__}: {exc}",
                audit=_audit(plan, options),
            )

        return ImpactExecutionResult(
            plan=plan,
            executed=True,
            success=bool(result.get("success")),
            output=str(result.get("content") or result.get("output") or ""),
            evidence=_evidence_from_result(result),
            warnings=[*plan.warnings, *[str(item) for item in _list_value(result.get("warnings"))]],
            error=str(result.get("error")) if result.get("error") else None,
            audit=_audit(plan, options),
        )


def _blocked_reason(plan: OperationPlan, options: ImpactExecutionOptions) -> str | None:
    if options.require_supported_capability and not plan.capability.supported:
        return plan.capability.unsupported_reason or "Capability is unsupported for this DBMS."
    if not plan.capability.execution_supported and plan.operation not in {FILE_WRITE, UDF_DROPPER}:
        return "This capability is marked assessment-only and has no built-in executor."
    if not options.allows(plan.operation):
        return f"Execution blocked: explicit allow flag is required for {plan.operation}."
    if plan.operation == FILE_READ and not plan.parameters.get("path"):
        return "Execution blocked: file_read requires a path."
    if plan.operation == OS_COMMAND and not plan.parameters.get("command"):
        return "Execution blocked: os_command requires a command."
    if plan.operation == FILE_WRITE:
        if not plan.parameters.get("path"):
            return "Execution blocked: file_write requires a destination path."
        if not any(key in plan.parameters for key in ("content", "data", "file_content")):
            return "Execution blocked: file_write requires content."
    return None


def _audit(plan: OperationPlan, options: ImpactExecutionOptions) -> dict[str, Any]:
    audit = plan.audit.to_dict()
    if options.operator:
        audit["operator"] = options.operator
    if options.reason:
        audit["reason"] = options.reason
    audit["allow_flags"] = {
        "file_read": options.allow_file_read,
        "file_write": options.allow_file_write,
        "os_command": options.allow_os_command,
        "udf_dropper": options.allow_udf_dropper,
    }
    return audit


def _evidence_from_result(result: dict[str, Any]) -> list[dict[str, Any]]:
    responses = cast(
        list[Any], result.get("responses") if isinstance(result.get("responses"), list) else []
    )
    evidence = []
    for item in responses:
        if isinstance(item, dict):
            evidence.append(
                {
                    "target": item.get("target"),
                    "elapsed": item.get("elapsed"),
                    "payload": item.get("payload"),
                    "error_hints": item.get("error_hints", []),
                    "truncated": bool(item.get("truncated")),
                }
            )
    return evidence


def _list_value(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


__all__ = ["OperatorGateError", "OperationRunner", "SessionImpactExecutor"]
