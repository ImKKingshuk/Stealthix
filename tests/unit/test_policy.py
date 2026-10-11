"""Unit tests for policy-as-code module."""

from __future__ import annotations

from pathlib import Path

import pytest

from stealthix.core.models import Finding
from stealthix.policy import (
    ComplianceGate,
    PolicyAction,
    PolicyConfig,
    PolicyEnforcer,
    PolicyLoader,
    PolicyRule,
    PolicyRuleType,
    load_policy,
)


def test_load_policy_valid_yaml(tmp_path: Path) -> None:
    """Test loading a valid policy YAML file."""
    policy_content = """
name: "Test Policy"
version: "1.0"
description: "Test policy for unit tests"
rules:
  - name: "CVSS Threshold"
    type: "cvss_threshold"
    threshold: 7.0
    operator: ">="
    action: "fail_scan"
    enabled: true
compliance:
  frameworks:
    - owasp_top_10
  strict_mode: false
"""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(policy_content)

    policy = load_policy(policy_file)

    assert policy.name == "Test Policy"
    assert policy.version == "1.0"
    assert len(policy.rules) == 1
    assert policy.rules[0].name == "CVSS Threshold"
    assert policy.rules[0].type == PolicyRuleType.CVSS_THRESHOLD
    assert policy.rules[0].threshold == 7.0
    assert policy.rules[0].action == PolicyAction.FAIL_SCAN


def test_load_policy_invalid_yaml(tmp_path: Path) -> None:
    """Test loading an invalid policy YAML file."""
    policy_file = tmp_path / "invalid_policy.yaml"
    policy_file.write_text("invalid: yaml: content:")

    with pytest.raises(ValueError, match="Invalid YAML"):
        load_policy(policy_file)


def test_load_policy_not_found(tmp_path: Path) -> None:
    """Test loading a non-existent policy file."""
    policy_file = tmp_path / "nonexistent.yaml"

    with pytest.raises(FileNotFoundError):
        load_policy(policy_file)


def test_load_policy_invalid_schema(tmp_path: Path) -> None:
    """Test loading a policy with invalid schema."""
    policy_content = """
name: "Test Policy"
rules:
  - name: "Invalid Rule"
    type: "invalid_type"
"""
    policy_file = tmp_path / "invalid_schema.yaml"
    policy_file.write_text(policy_content)

    with pytest.raises(ValueError, match="validation failed"):
        load_policy(policy_file)


def test_policy_loader_cache(tmp_path: Path) -> None:
    """Test policy loader caching."""
    policy_content = """
name: "Test Policy"
version: "1.0"
rules: []
"""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(policy_content)

    loader = PolicyLoader()

    policy1 = loader.load(policy_file)
    policy2 = loader.load(policy_file)

    assert policy1 is policy2  # Same object from cache


def test_policy_loader_clear_cache(tmp_path: Path) -> None:
    """Test clearing policy loader cache."""
    policy_content = """
name: "Test Policy"
version: "1.0"
rules: []
"""
    policy_file = tmp_path / "test_policy.yaml"
    policy_file.write_text(policy_content)

    loader = PolicyLoader()

    policy1 = loader.load(policy_file)
    loader.clear_cache()
    policy2 = loader.load(policy_file)

    assert policy1 is not policy2  # Different objects after cache clear


def test_policy_enforcer_cvss_threshold() -> None:
    """Test CVSS threshold policy enforcement."""
    policy = PolicyConfig(
        name="Test Policy",
        version="1.0",
        rules=[
            PolicyRule(
                name="High CVSS",
                type=PolicyRuleType.CVSS_THRESHOLD,
                threshold=7.0,
                operator=">=",
                action=PolicyAction.FAIL_SCAN,
                enabled=True,
            )
        ],
    )

    enforcer = PolicyEnforcer(policy)

    # Finding with high CVSS
    high_cvss_finding = Finding(
        kind="sqli-union",
        target="http://example.com",
        details={"cvss": 8.5},
    )

    violations = enforcer.enforce([high_cvss_finding])

    assert len(violations) == 1
    assert violations[0].rule_name == "High CVSS"
    assert violations[0].action == PolicyAction.FAIL_SCAN


def test_policy_enforcer_forbidden_kinds() -> None:
    """Test forbidden kinds policy enforcement."""
    policy = PolicyConfig(
        name="Test Policy",
        version="1.0",
        rules=[
            PolicyRule(
                name="Forbidden Union",
                type=PolicyRuleType.FORBIDDEN_KINDS,
                kinds=["sqli-union", "sqli-stacked"],
                action=PolicyAction.FAIL_SCAN,
                enabled=True,
            )
        ],
    )

    enforcer = PolicyEnforcer(policy)

    # Finding with forbidden kind
    forbidden_finding = Finding(
        kind="sqli-union",
        target="http://example.com",
        details={},
    )

    violations = enforcer.enforce([forbidden_finding])

    assert len(violations) == 1
    assert violations[0].rule_name == "Forbidden Union"
    assert "sqli-union" in violations[0].message


def test_policy_enforcer_compliance_gate() -> None:
    """Test compliance gate policy enforcement."""
    policy = PolicyConfig(
        name="Test Policy",
        version="1.0",
        rules=[
            PolicyRule(
                name="OWASP Compliance",
                type=PolicyRuleType.COMPLIANCE_GATE,
                framework="owasp_top_10",
                required=["A03:2021"],
                action=PolicyAction.FLAG_FINDING,
                enabled=True,
            )
        ],
    )

    enforcer = PolicyEnforcer(policy)

    # Finding without required compliance
    finding = Finding(
        kind="sqli-boolean",
        target="http://example.com",
        details={
            "cvss": 7.5,
            "compliance": {
                "owasp_top_10": [{"id": "A01:2021", "name": "Broken Access Control", "count": 1}],
            },
        },
    )

    violations = enforcer.enforce([finding])

    assert len(violations) == 1
    assert "A03:2021" in violations[0].message


def test_policy_enforcer_should_fail_scan() -> None:
    """Test should_fail_scan determination."""
    policy = PolicyConfig(
        name="Test Policy",
        version="1.0",
        rules=[
            PolicyRule(
                name="Critical Finding",
                type=PolicyRuleType.CVSS_THRESHOLD,
                threshold=9.0,
                operator=">=",
                action=PolicyAction.FAIL_SCAN,
                enabled=True,
            )
        ],
    )

    enforcer = PolicyEnforcer(policy)

    finding = Finding(
        kind="sqli-union",
        target="http://example.com",
        details={"cvss": 9.5},
    )

    violations = enforcer.enforce([finding])

    assert enforcer.should_fail_scan(violations) is True


def test_policy_enforcer_disabled_rule() -> None:
    """Test that disabled rules are not enforced."""
    policy = PolicyConfig(
        name="Test Policy",
        version="1.0",
        rules=[
            PolicyRule(
                name="Disabled Rule",
                type=PolicyRuleType.CVSS_THRESHOLD,
                threshold=5.0,
                operator=">=",
                action=PolicyAction.FAIL_SCAN,
                enabled=False,
            )
        ],
    )

    enforcer = PolicyEnforcer(policy)

    finding = Finding(
        kind="sqli-union",
        target="http://example.com",
        details={"cvss": 8.0},
    )

    violations = enforcer.enforce([finding])

    assert len(violations) == 0


def test_policy_validation_duplicate_rule_names() -> None:
    """Test that duplicate rule names are rejected."""
    with pytest.raises(ValueError, match="Duplicate rule names"):
        PolicyConfig(
            name="Test Policy",
            version="1.0",
            rules=[
                PolicyRule(
                    name="Duplicate",
                    type=PolicyRuleType.CVSS_THRESHOLD,
                    threshold=7.0,
                    action=PolicyAction.FLAG_FINDING,
                ),
                PolicyRule(
                    name="Duplicate",
                    type=PolicyRuleType.CVSS_THRESHOLD,
                    threshold=5.0,
                    action=PolicyAction.FLAG_FINDING,
                ),
            ],
        )


def test_policy_validation_invalid_operator() -> None:
    """Test that invalid operators are rejected."""
    with pytest.raises(ValueError, match="Invalid operator"):
        PolicyRule(
            name="Invalid Operator",
            type=PolicyRuleType.CVSS_THRESHOLD,
            threshold=7.0,
            operator="invalid",
            action=PolicyAction.FLAG_FINDING,
        )


def test_policy_validation_invalid_framework() -> None:
    """Test that invalid frameworks are rejected."""
    with pytest.raises(ValueError, match="Invalid framework"):
        PolicyRule(
            name="Invalid Framework",
            type=PolicyRuleType.COMPLIANCE_GATE,
            framework="invalid_framework",
            action=PolicyAction.FLAG_FINDING,
        )


def test_policy_enforcer_max_findings() -> None:
    """Test max findings aggregate policy rule."""
    policy = PolicyConfig(
        name="Test Max Findings",
        version="1.0",
        rules=[
            PolicyRule(
                name="Cap Findings",
                type=PolicyRuleType.MAX_FINDINGS,
                max_count=2,
                action=PolicyAction.FAIL_SCAN,
            )
        ],
    )
    enforcer = PolicyEnforcer(policy)
    findings = [
        Finding(kind="sqli-error", target="http://example.com/1"),
        Finding(kind="sqli-boolean", target="http://example.com/2"),
        Finding(kind="sqli-union", target="http://example.com/3"),
    ]
    violations = enforcer.enforce(findings)
    assert len(violations) == 1
    assert violations[0].action == PolicyAction.FAIL_SCAN
    assert "exceeds maximum allowed (2)" in violations[0].message
    assert violations[0].details["count"] == 3


def test_policy_enforcer_max_findings_by_kind() -> None:
    """Test max findings filtered by specific finding kinds."""
    policy = PolicyConfig(
        name="Test Max Union Findings",
        version="1.0",
        rules=[
            PolicyRule(
                name="Limit Union",
                type=PolicyRuleType.MAX_FINDINGS,
                kinds=["sqli-union"],
                max_count=1,
                action=PolicyAction.FAIL_SCAN,
            )
        ],
    )
    enforcer = PolicyEnforcer(policy)
    findings = [
        Finding(kind="sqli-error", target="http://example.com/1"),
        Finding(kind="sqli-error", target="http://example.com/2"),
        Finding(kind="sqli-union", target="http://example.com/3"),
    ]
    # Only 1 sqli-union finding, max_count is 1 -> passes
    assert len(enforcer.enforce(findings)) == 0

    # Add second sqli-union -> exceeds max_count
    findings.append(Finding(kind="sqli-union", target="http://example.com/4"))
    violations = enforcer.enforce(findings)
    assert len(violations) == 1
    assert violations[0].details["count"] == 2


def test_policy_enforcer_required_techniques() -> None:
    """Test required detection techniques enforcement."""
    policy = PolicyConfig(
        name="Test Techniques",
        version="1.0",
        rules=[
            PolicyRule(
                name="Require Union Technique",
                type=PolicyRuleType.REQUIRED_TECHNIQUES,
                techniques=["union"],
                action=PolicyAction.FLAG_FINDING,
            )
        ],
    )
    enforcer = PolicyEnforcer(policy)
    finding_without_union = Finding(
        kind="sqli-error",
        target="http://example.com",
        details={"techniques": ["error-based"]},
    )
    violations = enforcer.enforce([finding_without_union])
    assert len(violations) == 1
    assert "union" in violations[0].message

    finding_with_union = Finding(
        kind="sqli-union",
        target="http://example.com",
        details={"technique": "union"},
    )
    assert len(enforcer.enforce([finding_with_union])) == 0


def test_policy_enforcer_strict_compliance_gate() -> None:
    """Test root ComplianceGate in strict_mode."""
    policy = PolicyConfig(
        name="Strict Compliance",
        version="1.0",
        rules=[],
        compliance=ComplianceGate(
            frameworks=["owasp_top_10"],
            strict_mode=True,
        ),
    )
    enforcer = PolicyEnforcer(policy)
    unmapped_finding = Finding(
        kind="unmapped-vuln",
        target="http://example.com",
        details={},
    )
    violations = enforcer.enforce([unmapped_finding])
    assert len(violations) == 1
    assert violations[0].action == PolicyAction.FAIL_SCAN
    assert enforcer.should_fail_scan(violations) is True


def test_cli_parser_policy_option() -> None:
    """Test that --policy option is parsed by CLI parser."""
    from stealthix_headless_cli._parser import build_parser

    parser = build_parser()
    args = parser.parse_args(["scan", "-u", "http://example.com", "--policy", "/tmp/policy.yaml"])
    assert args.policy == "/tmp/policy.yaml"


def test_run_scan_with_policy_violation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test run_scan enforces policy and fails scan on violation."""
    import logging
    from types import SimpleNamespace

    from stealthix.core.models import ScanResult
    from stealthix.headless import run_scan

    policy_file = tmp_path / "strict_policy.yaml"
    policy_file.write_text("""
name: "Zero Tolerance"
rules:
  - name: "No Criticals"
    type: "cvss_threshold"
    threshold: 8.0
    operator: ">="
    action: "fail_scan"
""")

    args = SimpleNamespace(
        url="http://example.com",
        policy=str(policy_file),
        resume=None,
        session_load=None,
        session_save=None,
        url_file=None,
        crawl=False,
        api_schema=None,
        ws_url=None,
        report="json",
    )

    fake_result = ScanResult(
        target="http://example.com",
        findings=[
            Finding(kind="sqli-union", target="http://example.com", details={"cvss": 9.0})
        ],
    )
    monkeypatch.setattr("stealthix.core.engine.Engine.detect", lambda self: fake_result)

    result = run_scan(args, logging.getLogger("test"), {})
    assert result.exit_code == 1
    assert "policy_violations" in fake_result.metadata
    assert len(fake_result.metadata["policy_violations"]) == 1
    assert fake_result.metadata["policy_violations"][0]["rule_name"] == "No Criticals"


