"""Policy models for YAML-based policy definitions."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class PolicyRuleType(str, Enum):
    """Types of policy rules."""

    CVSS_THRESHOLD = "cvss_threshold"
    COMPLIANCE_GATE = "compliance_gate"
    FORBIDDEN_KINDS = "forbidden_kinds"
    MAX_FINDINGS = "max_findings"
    REQUIRED_TECHNIQUES = "required_techniques"


class PolicyAction(str, Enum):
    """Actions to take when a rule is violated."""

    FAIL_SCAN = "fail_scan"
    FLAG_FINDING = "flag_finding"
    WARN_ONLY = "warn_only"
    IGNORE = "ignore"


class PolicyRule(BaseModel):
    """A single policy rule."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Rule name")
    type: PolicyRuleType = Field(..., description="Rule type")
    action: PolicyAction = Field(default=PolicyAction.FLAG_FINDING, description="Action to take")
    enabled: bool = Field(default=True, description="Whether the rule is enabled")
    description: str | None = Field(default=None, description="Rule description")

    # CVSS threshold specific
    threshold: float | None = Field(
        default=None, ge=0.0, le=10.0, description="CVSS threshold value"
    )
    operator: str | None = Field(default=">=", description="Comparison operator (>=, >, <=, <, ==)")

    # Compliance gate specific
    framework: str | None = Field(
        default=None, description="Compliance framework (owasp_top_10, pci_dss_v4, nist_800_53)"
    )
    required: list[str] = Field(default_factory=list, description="Required compliance IDs")

    # Forbidden kinds specific
    kinds: list[str] = Field(default_factory=list, description="Forbidden finding kinds")

    # Max findings specific
    max_count: int | None = Field(default=None, ge=0, description="Maximum allowed findings")

    # Required techniques specific
    techniques: list[str] = Field(default_factory=list, description="Required detection techniques")

    @field_validator("operator")
    @classmethod
    def validate_operator(cls, v: str | None) -> str | None:
        """Validate comparison operator."""
        if v is None:
            return v
        valid_operators = {">=", ">", "<=", "<", "==", "!="}
        if v not in valid_operators:
            raise ValueError(f"Invalid operator: {v}. Must be one of {valid_operators}")
        return v

    @field_validator("framework")
    @classmethod
    def validate_framework(cls, v: str | None) -> str | None:
        """Validate compliance framework."""
        if v is None:
            return v
        valid_frameworks = {"owasp_top_10", "pci_dss_v4", "nist_800_53", "sans_top_25"}
        if v not in valid_frameworks:
            raise ValueError(f"Invalid framework: {v}. Must be one of {valid_frameworks}")
        return v


class ComplianceGate(BaseModel):
    """Compliance gate configuration."""

    model_config = ConfigDict(extra="forbid")

    frameworks: list[str] = Field(
        default_factory=list,
        description="Compliance frameworks to enforce (owasp_top_10, pci_dss_v4, nist_800_53)",
    )
    strict_mode: bool = Field(default=False, description="Fail scan if compliance gate not met")


class PolicyConfig(BaseModel):
    """Root policy configuration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Policy name")
    version: str = Field(default="1.0", description="Policy version")
    description: str | None = Field(default=None, description="Policy description")
    rules: list[PolicyRule] = Field(default_factory=list, description="Policy rules")
    compliance: ComplianceGate = Field(
        default_factory=ComplianceGate, description="Compliance gate configuration"
    )

    @field_validator("rules")
    @classmethod
    def validate_rules(cls, v: list[PolicyRule]) -> list[PolicyRule]:
        """Validate rule consistency."""
        # Check for duplicate rule names
        names = [rule.name for rule in v]
        if len(names) != len(set(names)):
            raise ValueError("Duplicate rule names detected")
        return v


__all__ = [
    "PolicyRuleType",
    "PolicyAction",
    "PolicyRule",
    "ComplianceGate",
    "PolicyConfig",
]
