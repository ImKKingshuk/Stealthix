from __future__ import annotations

import datetime as _dt
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any, Protocol

from stealthix.core.evidence import body_digest, excerpt

ImpactOperation = str

FILE_READ: ImpactOperation = "file_read"
FILE_WRITE: ImpactOperation = "file_write"
OS_COMMAND: ImpactOperation = "os_command"
UDF_DROPPER: ImpactOperation = "udf_dropper"

IMPACT_OPERATIONS = (FILE_READ, FILE_WRITE, OS_COMMAND, UDF_DROPPER)

_SENSITIVE_PARAMETER_KEYS = {"command", "content", "data", "payload", "file_content"}


def utc_now() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat()


def redact_parameters(parameters: Mapping[str, Any]) -> dict[str, Any]:
    redacted: dict[str, Any] = {}
    for key, value in parameters.items():
        normalized = str(key).strip().lower()
        if normalized in {"content", "data", "file_content"}:
            redacted[str(key)] = {
                "sha256": body_digest(value),
                "bytes": len(value if isinstance(value, bytes) else str(value).encode()),
            }
        elif normalized in _SENSITIVE_PARAMETER_KEYS:
            redacted[str(key)] = excerpt(value, limit=120)
        else:
            redacted[str(key)] = value
    return redacted


@dataclass(frozen=True)
class Capability:
    operation: ImpactOperation
    supported: bool
    summary: str
    primitives: tuple[str, ...] = ()
    requires_stacked: bool = False
    required_privileges: tuple[str, ...] = ()
    required_features: tuple[str, ...] = ()
    execution_supported: bool = True
    destructive: bool = False
    unsupported_reason: str | None = None
    evidence_hints: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def feasible(self) -> bool:
        return self.supported

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation": self.operation,
            "supported": self.supported,
            "feasible": self.feasible,
            "summary": self.summary,
            "primitives": list(self.primitives),
            "requires_stacked": self.requires_stacked,
            "required_privileges": list(self.required_privileges),
            "required_features": list(self.required_features),
            "execution_supported": self.execution_supported,
            "destructive": self.destructive,
            "evidence_hints": list(self.evidence_hints),
            "notes": list(self.notes),
        }
        if self.unsupported_reason:
            payload["unsupported_reason"] = self.unsupported_reason
        return payload


@dataclass(frozen=True)
class CapabilityProfile:
    dbms: str
    family: str
    aliases: tuple[str, ...] = ()
    capabilities: Mapping[ImpactOperation, Capability] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    def capability(self, operation: ImpactOperation) -> Capability:
        if operation not in IMPACT_OPERATIONS:
            raise ValueError(f"Unknown impact operation: {operation}")
        if operation in self.capabilities:
            return self.capabilities[operation]
        return Capability(
            operation=operation,
            supported=False,
            summary=f"{operation} is not modeled for {self.dbms}.",
            execution_supported=False,
            unsupported_reason="No backend-specific capability profile exists for this operation.",
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "dbms": self.dbms,
            "family": self.family,
            "aliases": list(self.aliases),
            "capabilities": {
                operation: self.capability(operation).to_dict() for operation in IMPACT_OPERATIONS
            },
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class OperationStep:
    name: str
    description: str
    kind: str = "operator_action"
    destructive: bool = False
    requires_confirmation: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "kind": self.kind,
            "destructive": self.destructive,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass(frozen=True)
class AuditMetadata:
    created_at: str = field(default_factory=utc_now)
    operator: str | None = None
    target: str | None = None
    reason: str | None = None
    source: str = "stealthix-impact"
    labels: tuple[str, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "created_at": self.created_at,
            "source": self.source,
            "labels": list(self.labels),
            "evidence": dict(self.evidence),
        }
        if self.operator:
            payload["operator"] = self.operator
        if self.target:
            payload["target"] = self.target
        if self.reason:
            payload["reason"] = self.reason
        return payload


@dataclass(frozen=True)
class OperationPlan:
    dbms: str
    operation: ImpactOperation
    capability: Capability
    parameters: Mapping[str, Any] = field(default_factory=dict)
    steps: tuple[OperationStep, ...] = ()
    audit: AuditMetadata = field(default_factory=AuditMetadata)
    warnings: tuple[str, ...] = ()
    plan_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: str = "planned"

    @property
    def executable(self) -> bool:
        return self.capability.supported and self.capability.execution_supported

    def fingerprint(self) -> str:
        material = "|".join(
            [
                self.plan_id,
                self.dbms,
                self.operation,
                str(redact_parameters(self.parameters)),
                self.audit.created_at,
            ]
        )
        return sha256(material.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "fingerprint": self.fingerprint(),
            "status": self.status,
            "dbms": self.dbms,
            "operation": self.operation,
            "executable": self.executable,
            "parameters": redact_parameters(self.parameters),
            "capability": self.capability.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "audit": self.audit.to_dict(),
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True)
class ImpactExecutionOptions:
    allow_file_read: bool = False
    allow_file_write: bool = False
    allow_os_command: bool = False
    allow_udf_dropper: bool = False
    require_supported_capability: bool = True
    operator: str | None = None
    reason: str | None = None

    def allows(self, operation: ImpactOperation) -> bool:
        return {
            FILE_READ: self.allow_file_read,
            FILE_WRITE: self.allow_file_write,
            OS_COMMAND: self.allow_os_command,
            UDF_DROPPER: self.allow_udf_dropper,
        }.get(operation, False)


@dataclass
class ImpactExecutionResult:
    plan: OperationPlan
    executed: bool = False
    success: bool = False
    output: str = ""
    evidence: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    error: str | None = None
    audit: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "operation": self.plan.operation,
            "dbms": self.plan.dbms,
            "executed": self.executed,
            "success": self.success,
            "output": self.output,
            "evidence": list(self.evidence),
            "warnings": list(self.warnings),
            "plan": self.plan.to_dict(),
            "audit": self.audit or self.plan.audit.to_dict(),
        }
        if self.error:
            payload["error"] = self.error
        return payload


class ImpactExecutor(Protocol):
    def execute(
        self, plan: OperationPlan, options: ImpactExecutionOptions
    ) -> ImpactExecutionResult: ...
