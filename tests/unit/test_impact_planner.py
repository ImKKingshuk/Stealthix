from __future__ import annotations

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.impact import (
    FILE_READ,
    OS_COMMAND,
    ImpactExecutionOptions,
    SessionImpactExecutor,
    get_capability,
    plan_impact_operation,
)


def test_impact_profiles_model_dbms_specific_capabilities() -> None:
    mysql_read = get_capability("mysql", FILE_READ)
    assert mysql_read.supported is True
    assert "LOAD_FILE" in mysql_read.primitives

    sqlite_os = get_capability("sqlite", OS_COMMAND)
    assert sqlite_os.supported is False
    assert sqlite_os.execution_supported is False

    mssql_os = get_capability("sqlserver", OS_COMMAND)
    assert mssql_os.supported is True
    assert "xp_cmdshell" in mssql_os.primitives


def test_impact_plan_redacts_sensitive_parameters() -> None:
    plan = plan_impact_operation(
        "postgresql",
        OS_COMMAND,
        parameters={"command": "id && hostname"},
        operator="alice",
        reason="authorized-test",
    )

    payload = plan.to_dict()
    assert payload["operation"] == OS_COMMAND
    assert payload["parameters"]["command"] == "id && hostname"
    assert payload["audit"]["operator"] == "alice"
    assert any("Required privileges" in warning for warning in payload["warnings"])


def test_session_impact_executor_requires_matching_allow_flag(monkeypatch) -> None:
    session = ScanSession(SessionConfig(base_url="http://example.com/?id=1", dbms="mysql"))
    plan = plan_impact_operation("mysql", FILE_READ, parameters={"path": "/etc/passwd"})

    blocked = SessionImpactExecutor(session).execute(plan, ImpactExecutionOptions())

    assert blocked.executed is False
    assert blocked.success is False
    assert "explicit allow flag" in str(blocked.error)

    monkeypatch.setattr(
        "stealthix.impact.executor.read_file",
        lambda _session, path: {
            "success": True,
            "content": f"content from {path}",
            "responses": [{"target": "http://example.com", "elapsed": 0.01, "payload": "p"}],
            "warnings": [],
        },
    )

    executed = SessionImpactExecutor(session).execute(
        plan,
        ImpactExecutionOptions(allow_file_read=True, operator="alice", reason="ticket-1"),
    )

    assert executed.executed is True
    assert executed.success is True
    assert "content from /etc/passwd" in executed.output
    assert executed.audit["operator"] == "alice"
