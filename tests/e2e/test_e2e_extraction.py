"""End-to-end tests for data extraction."""

from stealthix.core.session import ScanSession, SessionConfig


def test_e2e_extraction_session_setup(mock_server):
    """Test extraction session setup with mock server."""
    config = SessionConfig(base_url=f"{mock_server.url}/api/data", dbms="postgresql", level=2)
    session = ScanSession(config)

    assert session.config.dbms == "postgresql"
    assert session.config.level == 2


def test_e2e_extraction_with_mock_response(mock_server):
    """Test extraction with mock server response."""
    config = SessionConfig(
        base_url=f"{mock_server.url}/api/search", method="POST", body_format="json"
    )
    session = ScanSession(config)

    assert session.config.method == "POST"
    assert session.config.body_format == "json"
