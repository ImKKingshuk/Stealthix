import json

import pytest

from stealthix.core.errors import CredentialError
from stealthix.core.session import ScanSession, SessionConfig


def test_session_save_load_redacts_secrets_by_default(tmp_path):
    config = SessionConfig(
        base_url="http://example.com",
        headers={"X-Test": "1"},
        cookies={"sid": "cookie-1"},
        threads=8,
        pool_maxsize=16,
        auth_type="form",
        auth_token="token-1",
        auth_config={"login_url": "/login", "username": "alice", "password": "secret"},
        api_schema="schema.yaml",
        api_schema_format="openapi",
        api_header_params=["X-Tenant"],
        ws_url="ws://example.com/socket",
        ws_messages=['{"ping":1}'],
        ws_headers={"X-WS": "1"},
        ws_subprotocols=["graphql-ws"],
        ws_timeout=7.5,
    )
    session = ScanSession(config=config, metadata={"key": "value"})
    session.creds.add("token", "secret")
    session.history.add("http://example.com", "GET", "200", 0.1)
    path = tmp_path / "session.json"
    session.save(str(path), include_secrets=False)
    saved = json.loads(path.read_text(encoding="utf-8"))

    assert saved["secrets_redacted"] is True
    assert saved["config"]["auth_token"] == "***REDACTED***"
    assert saved["config"]["auth_config"]["password"] == "***REDACTED***"
    assert saved["config"]["cookies"]["sid"] == "***REDACTED***"
    assert saved["creds"]["secrets"]["token"] == "***REDACTED***"

    loaded = ScanSession.load(str(path))
    assert loaded.config.base_url == "http://example.com"
    assert loaded.config.threads == 8
    assert loaded.config.pool_maxsize == 16
    assert loaded.config.auth_type == "form"
    assert loaded.config.auth_token is None
    assert loaded.config.auth_config["login_url"] == "/login"
    assert loaded.config.auth_config["password"] is None
    assert loaded.config.api_schema == "schema.yaml"
    assert loaded.config.api_header_params == ["X-Tenant"]
    assert loaded.config.ws_url == "ws://example.com/socket"
    assert loaded.config.ws_subprotocols == ["graphql-ws"]
    assert loaded.config.ws_timeout == 7.5
    assert loaded.metadata["key"] == "value"
    assert loaded.creds.get("token") is None
    assert loaded.history.entries


def test_session_private_payload_preserves_runtime_secrets_for_internal_use():
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_type="bearer",
            auth_token="token-1",
            auth_config={"password": "secret"},
        )
    )
    session.creds.add("token", "secret")

    payload = session.to_private_payload()

    assert payload["secrets_redacted"] is False
    assert payload["config"]["auth_token"] == "token-1"
    assert payload["config"]["auth_config"]["password"] == "secret"
    assert payload["creds"]["secrets"]["token"] == "secret"


def test_credential_store_encrypted(tmp_path):
    config = SessionConfig(base_url="http://example.com")
    session = ScanSession(config=config)
    session.creds.add("api_key", "value")
    path = tmp_path / "creds.enc"
    session.creds.save_encrypted(str(path), "passphrase")
    new_store = session.creds.__class__()
    new_store.load_encrypted(str(path), "passphrase")
    assert new_store.get("api_key") == "value"


def test_credential_store_encrypted_rejects_wrong_passphrase(tmp_path):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.creds.add("api_key", "value")
    path = tmp_path / "creds.enc"
    session.creds.save_encrypted(str(path), "passphrase")

    new_store = session.creds.__class__()
    with pytest.raises(CredentialError):
        new_store.load_encrypted(str(path), "wrong-passphrase")


def test_merge_worker_state_propagates_auth_updates():
    parent = ScanSession(
        SessionConfig(
            base_url="http://example.com", auth_type="bearer", auth_config={"scheme": "Bearer"}
        )
    )
    worker = parent.clone_for_worker()
    worker.config.auth_token = "token-2"
    worker.config.cookies["sid"] = "cookie-1"
    worker.config.headers["Authorization"] = "Bearer token-2"
    worker.metadata["auth"] = {"authenticated": True}

    parent.merge_worker_state(worker)

    assert parent.config.auth_token == "token-2"
    assert parent.config.cookies["sid"] == "cookie-1"
    assert parent.metadata["auth"]["authenticated"] is True
