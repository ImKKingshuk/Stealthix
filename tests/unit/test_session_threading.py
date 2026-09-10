"""Test session thread safety and serialization."""

import pytest

from stealthix.core.session import ScanSession, SessionConfig


def test_session_threading_metadata_update():
    """Test thread-safe metadata update."""
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    session._safe_metadata_update("test_key", "test_value")
    assert session._safe_metadata_get("test_key") == "test_value"


def test_session_threading_metadata_get_with_default():
    """Test thread-safe metadata get with default value."""
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    assert session._safe_metadata_get("nonexistent", "default") == "default"
    assert session._safe_metadata_get("nonexistent") is None


def test_session_threading_metadata_merge():
    """Test thread-safe metadata merge."""
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["key1"] = "value1"

    session._safe_metadata_merge({"key2": "value2", "key3": "value3"})

    assert session.metadata["key1"] == "value1"
    assert session.metadata["key2"] == "value2"
    assert session.metadata["key3"] == "value3"


def test_session_clone_for_worker_copies_metadata():
    """Test that clone_for_worker copies metadata safely."""
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["key1"] = "value1"
    session.metadata["key2"] = "value2"

    worker = session.clone_for_worker()

    assert worker.metadata == {"key1": "value1", "key2": "value2"}
    # Modifying worker should not affect original
    worker.metadata["key3"] = "value3"
    assert "key3" not in session.metadata


def test_session_merge_worker_state_thread_safe():
    """Test that merge_worker_state is thread-safe."""
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["key1"] = "value1"

    worker = ScanSession(SessionConfig(base_url="http://example.com"))
    worker.metadata["key2"] = "value2"
    worker.config.cookies = {"session": "worker123"}

    session.merge_worker_state(worker)

    assert session.metadata["key1"] == "value1"
    assert session.metadata["key2"] == "value2"
    assert session.config.cookies["session"] == "worker123"


def test_session_config_redacts_auth_token():
    """Test that SessionConfig.to_dict_redacted() redacts auth_token."""
    config = SessionConfig(base_url="http://example.com", auth_token="secret_token")
    result = config.to_dict_redacted()

    assert result["auth_token"] == "***REDACTED***"


def test_session_config_redacts_password_in_auth_config():
    """Test that SessionConfig.to_dict_redacted() redacts password in auth_config."""
    config = SessionConfig(
        base_url="http://example.com", auth_config={"username": "test", "password": "secret123"}
    )
    result = config.to_dict_redacted()

    assert result["auth_config"]["password"] == "***REDACTED***"
    assert result["auth_config"]["username"] == "test"


def test_session_config_redacts_multiple_sensitive_keys():
    """Test that multiple sensitive keys are redacted."""
    config = SessionConfig(
        base_url="http://example.com",
        auth_config={
            "username": "test",
            "password": "secret",
            "secret": "mysecret",
            "api_key": "apikey123",
            "token": "token456",
        },
    )
    result = config.to_dict_redacted()

    assert result["auth_config"]["password"] == "***REDACTED***"
    assert result["auth_config"]["secret"] == "***REDACTED***"
    assert result["auth_config"]["api_key"] == "***REDACTED***"
    assert result["auth_config"]["token"] == "***REDACTED***"
    assert result["auth_config"]["username"] == "test"


def test_session_config_redaction_handles_none_auth_config():
    """Test redaction handles None auth_config."""
    config = SessionConfig(base_url="http://example.com", auth_config=None)
    result = config.to_dict_redacted()

    assert result["auth_config"] is None


def test_session_config_redaction_handles_empty_auth_config():
    """Test redaction handles empty auth_config."""
    config = SessionConfig(base_url="http://example.com", auth_config={})
    result = config.to_dict_redacted()

    assert result["auth_config"] is None


def test_session_to_payload_redacts_sensitive_fields():
    """Test that session.to_dict_redacted() redacts sensitive fields."""
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com",
            auth_token="secret_token",
            auth_config={"username": "test", "password": "secret"},
        )
    )

    redacted = session.config.to_dict_redacted()

    assert redacted["auth_token"] == "***REDACTED***"
    assert redacted["auth_config"]["password"] == "***REDACTED***"
    assert redacted["auth_config"]["username"] == "test"
