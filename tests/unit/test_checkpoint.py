from stealthix.core.checkpoint import (
    CheckpointManager,
    deserialize_findings,
    load_checkpoint,
    restore_session,
    serialize_findings,
)
from stealthix.core.models import Finding
from stealthix.core.session import ScanSession, SessionConfig


def test_checkpoint_round_trip_preserves_session_and_findings(tmp_path):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="bearer",
            auth_token="token-1",
            auth_config={"password": "secret"},
        ),
        metadata={"phase": 9},
    )
    session.creds.add("token", "secret")
    session.runtime["simple"] = {"enabled": True}
    findings = [
        Finding(
            kind="sqli-error",
            target="http://example.com/?id=1",
            parameter="id",
            location="query",
            details={"payload": "'"},
        )
    ]
    manager = CheckpointManager(tmp_path / "scan.stx", interval_seconds=0)

    assert manager.save_snapshot(
        session,
        mode="detect",
        status="running",
        state={"findings": serialize_findings(findings)},
        input_context={"base_url": session.config.base_url},
        force=True,
    )

    payload = load_checkpoint(tmp_path / "scan.stx")
    assert payload["session"]["secrets_redacted"] is True
    assert payload["session"]["config"]["auth_token"] == "***REDACTED***"
    assert payload["session"]["config"]["auth_config"]["password"] == "***REDACTED***"
    assert payload["session"]["creds"]["secrets"]["token"] == "***REDACTED***"
    restored_session = restore_session(payload["session"])
    restored_findings = deserialize_findings(payload["state"]["findings"])

    assert restored_session.config.base_url == "http://example.com"
    assert restored_session.config.auth_token is None
    assert restored_session.config.auth_config["password"] is None
    assert restored_session.creds.get("token") is None
    assert restored_session.metadata["phase"] == 9
    assert restored_session.runtime["simple"] == {"enabled": True}
    assert restored_findings[0].parameter == "id"
