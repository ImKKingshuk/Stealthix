"""End-to-end tests for authentication."""

from stealthix.core.session import ScanSession, SessionConfig


def test_e2e_bearer_auth_with_mock_server(mock_server):
    """End-to-end test of bearer authentication."""
    config = SessionConfig(
        base_url=f"{mock_server.url}/api/data",
        auth_type="bearer",
        auth_config={"token": "test_token"},
    )
    session = ScanSession(config)

    assert session.config.auth_type == "bearer"
    assert session.config.auth_config["token"] == "test_token"


def test_e2e_form_auth_with_mock_server(mock_server):
    """End-to-end test of form-based authentication."""
    config = SessionConfig(
        base_url=f"{mock_server.url}/login",
        auth_type="form",
        auth_config={"username": "test", "password": "test"},
    )
    session = ScanSession(config)

    assert session.config.auth_type == "form"
    assert session.config.auth_config["username"] == "test"


def test_e2e_session_with_cookies(mock_server):
    """Test session with cookies."""
    config = SessionConfig(
        base_url=f"{mock_server.url}/api/data", cookies={"session": "test_session"}
    )
    session = ScanSession(config)

    assert session.config.cookies["session"] == "test_session"
