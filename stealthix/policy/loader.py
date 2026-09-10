"""Policy loader for YAML-based policy definitions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import structlog
import yaml

from stealthix.policy.models import PolicyConfig

logger = structlog.get_logger(__name__)


def load_policy(file_path: str | Path) -> PolicyConfig:
    """
    Load a policy from a YAML file.

    Args:
        file_path: Path to the YAML policy file

    Returns:
        Validated PolicyConfig object

    Raises:
        FileNotFoundError: If policy file doesn't exist
        ValueError: If policy YAML is invalid
    """
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    try:
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML in policy file: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("Policy YAML must be a dictionary")

    try:
        policy = PolicyConfig(**data)
        logger.info(
            "policy_loaded",
            name=policy.name,
            version=policy.version,
            rules_count=len(policy.rules),
        )
        return policy
    except Exception as e:
        raise ValueError(f"Policy validation failed: {e}") from e


def merge_policies(base_policy: PolicyConfig, override_policy: PolicyConfig) -> PolicyConfig:
    """
    Merge two policies, with override taking precedence.

    Args:
        base_policy: Base policy
        override_policy: Override policy

    Returns:
        Merged PolicyConfig
    """
    merged_rules = list(base_policy.rules)

    # Add or override rules from override policy
    existing_rule_names = {rule.name for rule in merged_rules}
    for rule in override_policy.rules:
        if rule.name in existing_rule_names:
            # Replace existing rule
            merged_rules = [r for r in merged_rules if r.name != rule.name]
        merged_rules.append(rule)

    # Merge compliance gates
    merged_frameworks = list(
        set(base_policy.compliance.frameworks + override_policy.compliance.frameworks)
    )
    merged_compliance = override_policy.compliance.model_copy(
        update={
            "frameworks": merged_frameworks,
            "strict_mode": override_policy.compliance.strict_mode,
        }
    )

    return PolicyConfig(
        name=override_policy.name or base_policy.name,
        version=override_policy.version or base_policy.version,
        description=override_policy.description or base_policy.description,
        rules=merged_rules,
        compliance=merged_compliance,
    )


class PolicyLoader:
    """Policy loader with caching and directory support."""

    def __init__(self) -> None:
        """Initialize policy loader."""
        self._cache: dict[str, PolicyConfig] = {}

    def load(self, file_path: str | Path, use_cache: bool = True) -> PolicyConfig:
        """
        Load policy from file with optional caching.

        Args:
            file_path: Path to policy file
            use_cache: Whether to use cached policy if available

        Returns:
            PolicyConfig object
        """
        path_str = str(file_path)

        if use_cache and path_str in self._cache:
            return self._cache[path_str]

        policy = load_policy(file_path)

        if use_cache:
            self._cache[path_str] = policy

        return policy

    def load_from_directory(self, directory: str | Path, merge: bool = True) -> PolicyConfig:
        """
        Load and merge all policy files from a directory.

        Args:
            directory: Directory containing policy files
            merge: Whether to merge multiple policies into one

        Returns:
            Merged PolicyConfig or first policy if merge=False
        """
        dir_path = Path(directory)
        if not dir_path.exists() or not dir_path.is_dir():
            raise ValueError(f"Policy directory not found: {directory}")

        policy_files = sorted(dir_path.glob("*.yaml")) + sorted(dir_path.glob("*.yml"))

        if not policy_files:
            raise ValueError(f"No policy files found in directory: {directory}")

        if not merge:
            return self.load(policy_files[0])

        # Merge all policies
        base_policy = self.load(policy_files[0])
        for policy_file in policy_files[1:]:
            override_policy = self.load(policy_file)
            base_policy = merge_policies(base_policy, override_policy)

        logger.info(
            "policies_merged",
            directory=str(directory),
            file_count=len(policy_files),
            final_rules=len(base_policy.rules),
        )

        return base_policy

    def clear_cache(self) -> None:
        """Clear policy cache."""
        self._cache.clear()


__all__ = [
    "load_policy",
    "merge_policies",
    "PolicyLoader",
]
