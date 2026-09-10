"""Pytest fixtures for E2E tests."""

import pytest

from tests.e2e.fixtures.mock_targets import MockServer


@pytest.fixture
def mock_server():
    """Start a mock HTTP server for testing."""
    server = MockServer(port=8888)
    server.start()
    yield server
    server.stop()
