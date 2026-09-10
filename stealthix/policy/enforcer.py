"""Policy enforcer for scan-time policy validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import structlog

from stealthix.core.models import Finding
from stealthix.policy.models import PolicyAction, PolicyConfig, PolicyRule, PolicyRuleType

logger = structlog.get_logger(__name__)


@dataclass
class PolicyViolation:
    """Represents a policy rule violation."""

    rule_name: str
    rule_type: PolicyRuleType
    action: PolicyAction
    message: str
    finding: Finding | None = None
    details: dict[str, Any] | None = None


class PolicyEnforcer:
    """Enforces policy rules against scan findings."""

    def __init__(self, policy: PolicyConfig) -> None:
        """Initialize policy enforcer.

        Args:
            policy: Policy configuration to enforce
        """
        self.policy = policy

    def enforce(self, findings: list[Finding]) -> list[PolicyViolation]:
        """
        Enforce policy rules against findings.

        Args:
            findings: List of scan findings

        Returns:
            List of policy violations
        """
        violations: list[PolicyViolation] = []

        for rule in self.policy.rules:
            if not rule.enabled:
                continue

            for finding in findings:
                violation = self._check_rule(rule, finding)
                if violation:
                    violations.append(violation)

        logger.info(
            "policy_enforced",
            policy_name=self.policy.name,
            findings_count=len(findings),
            violations_count=len(violations),
        )

        return violations

    def should_fail_scan(self, violations: list[PolicyViolation]) -> bool:
        """
        Determine if scan should fail based on violations.

        Args:
            violations: List of policy violations

        Returns:
            True if scan should fail
        """
        return any(v.action == PolicyAction.FAIL_SCAN for v in violations)

    def _check_rule(self, rule: PolicyRule, finding: Finding) -> PolicyViolation | None:
        """Check a single rule against a finding.

        Args:
            rule: Policy rule to check
            finding: Finding to check against

        Returns:
            PolicyViolation if rule violated, None otherwise
        """
        details = finding.details if isinstance(finding.details, dict) else {}
        cvss = float(details.get("cvss", 0.0) or 0.0)

        if rule.type == PolicyRuleType.CVSS_THRESHOLD:
            return self._check_cvss_threshold(rule, finding, cvss)

        if rule.type == PolicyRuleType.COMPLIANCE_GATE:
            return self._check_compliance_gate(rule, finding, details)

        if rule.type == PolicyRuleType.FORBIDDEN_KINDS:
            return self._check_forbidden_kinds(rule, finding)

        if rule.type == PolicyRuleType.REQUIRED_TECHNIQUES:
            return self._check_required_techniques(rule, finding, details)

        return None

    def _check_cvss_threshold(
        self, rule: PolicyRule, finding: Finding, cvss: float
    ) -> PolicyViolation | None:
        """Check CVSS threshold rule.

        Args:
            rule: CVSS threshold rule
            finding: Finding to check
            cvss: CVSS score of finding

        Returns:
            PolicyViolation if violated, None otherwise
        """
        if rule.threshold is None:
            return None

        operator = rule.operator or ">="

        if operator == ">=" and cvss >= rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} exceeds threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        if operator == ">" and cvss > rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} exceeds threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        if operator == "<=" and cvss <= rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} below threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        if operator == "<" and cvss < rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} below threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        if operator == "==" and cvss == rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} equals threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        if operator == "!=" and cvss != rule.threshold:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"CVSS score {cvss:.1f} does not equal threshold {rule.threshold}",
                finding=finding,
                details={"cvss": cvss, "threshold": rule.threshold, "operator": operator},
            )

        return None

    def _check_compliance_gate(
        self, rule: PolicyRule, finding: Finding, details: dict[str, Any]
    ) -> PolicyViolation | None:
        """Check compliance gate rule.

        Args:
            rule: Compliance gate rule
            finding: Finding to check
            details: Finding details

        Returns:
            PolicyViolation if violated, None otherwise
        """
        if not rule.framework or not rule.required:
            return None

        # Get compliance mapping from finding
        compliance = details.get("compliance")
        if not isinstance(compliance, dict):
            return None

        framework_data = compliance.get(rule.framework)
        if not framework_data:
            return None

        # Handle both list and dict structures
        framework_ids = []
        if isinstance(framework_data, list):
            framework_ids = [item.get("id", "") for item in framework_data]
        elif isinstance(framework_data, dict):
            framework_ids = [item.get("id", "") for item in framework_data.values()]

        # Check if required compliance IDs are present
        missing = set(rule.required) - set(framework_ids)

        if missing:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"Missing required compliance IDs: {', '.join(missing)}",
                finding=finding,
                details={
                    "framework": rule.framework,
                    "required": rule.required,
                    "present": framework_ids,
                    "missing": list(missing),
                },
            )

        return None

    def _check_forbidden_kinds(self, rule: PolicyRule, finding: Finding) -> PolicyViolation | None:
        """Check forbidden finding kinds rule.

        Args:
            rule: Forbidden kinds rule
            finding: Finding to check

        Returns:
            PolicyViolation if violated, None otherwise
        """
        if not rule.kinds:
            return None

        if finding.kind in rule.kinds:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"Forbidden finding kind: {finding.kind}",
                finding=finding,
                details={"kind": finding.kind, "forbidden_kinds": rule.kinds},
            )

        return None

    def _check_required_techniques(
        self, rule: PolicyRule, finding: Finding, details: dict[str, Any]
    ) -> PolicyViolation | None:
        """Check required detection techniques rule.

        Args:
            rule: Required techniques rule
            finding: Finding to check
            details: Finding details

        Returns:
            PolicyViolation if violated, None otherwise
        """
        if not rule.techniques:
            return None

        techniques = details.get("techniques", [])
        if not isinstance(techniques, list):
            techniques = []

        required_lower = [t.lower() for t in rule.techniques]
        techniques_lower = [t.lower() for t in techniques]

        missing = set(required_lower) - set(techniques_lower)

        if missing:
            return PolicyViolation(
                rule_name=rule.name,
                rule_type=rule.type,
                action=rule.action,
                message=f"Missing required detection techniques: {', '.join(missing)}",
                finding=finding,
                details={
                    "required": rule.techniques,
                    "present": techniques,
                    "missing": list(missing),
                },
            )

        return None


__all__ = [
    "PolicyViolation",
    "PolicyEnforcer",
]
