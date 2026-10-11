"""Policy-as-code module for Stealthix.

This module provides YAML-based policy definitions for scan enforcement,
including auto-fail conditions and compliance gates.
"""

from stealthix.policy.enforcer import PolicyEnforcer, PolicyViolation
from stealthix.policy.loader import PolicyLoader, load_policy
from stealthix.policy.models import (
    ComplianceGate,
    PolicyAction,
    PolicyConfig,
    PolicyRule,
    PolicyRuleType,
)

__all__ = [
    "ComplianceGate",
    "PolicyAction",
    "PolicyConfig",
    "PolicyEnforcer",
    "PolicyLoader",
    "PolicyRule",
    "PolicyRuleType",
    "PolicyViolation",
    "load_policy",
]
