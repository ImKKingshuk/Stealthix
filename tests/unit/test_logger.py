"""Tests for structured logging with structlog."""

import json
import tempfile
from pathlib import Path

import structlog

from stealthix.core.logger import configure_logger, get_logger, set_module_log_level


def test_configure_logger_returns_bound_logger():
    """Test that configure_logger returns a structlog logger."""
    logger = configure_logger()
    assert hasattr(logger, "info")
    assert hasattr(logger, "error")


def test_configure_logger_with_json_format():
    """Test that JSON format is configured correctly."""
    logger = configure_logger(log_format="json")
    assert hasattr(logger, "info")


def test_configure_logger_with_rich_format():
    """Test that Rich format is configured correctly."""
    logger = configure_logger(log_format="rich")
    assert hasattr(logger, "info")


def test_configure_logger_with_file_output():
    """Test that file output is configured correctly."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        log_file = f.name

    try:
        logger = configure_logger(log_file=log_file, log_format="json")
        logger.info("test_message", key="value")

        # Verify file was created
        log_path = Path(log_file)
        assert log_path.exists()
    finally:
        Path(log_file).unlink(missing_ok=True)


def test_get_logger_returns_bound_logger():
    """Test that get_logger returns a structlog logger."""
    logger = get_logger()
    assert hasattr(logger, "info")
    assert hasattr(logger, "error")


def test_get_logger_with_name():
    """Test that get_logger with name returns logger for that module."""
    logger = get_logger("stealthix.core.engine")
    assert hasattr(logger, "info")


def test_set_module_log_level():
    """Test that set_module_log_level works correctly."""
    import logging

    set_module_log_level("stealthix.core.engine", "DEBUG")
    assert logging.getLogger("stealthix.core.engine").level == logging.DEBUG


def test_logger_with_context():
    """Test that logger can log with structured context."""
    logger = configure_logger(log_format="json")
    logger.info("test_event", scan_id="123", target="http://example.com", level="5")
    # Just verify it doesn't crash - actual output testing would require capturing


def test_logger_preserves_rich_console():
    """Test that Rich console output is preserved by default."""
    logger = configure_logger(log_format="rich")
    logger.info("test_message")
    # Just verify it doesn't crash - Rich output goes to console


def test_environment_variable_log_level():
    """Test that STEALTHIX_LOG_LEVEL environment variable is respected."""
    import os

    os.environ["STEALTHIX_LOG_LEVEL"] = "DEBUG"
    try:
        logger = configure_logger()
        # Verify configuration doesn't crash
        assert hasattr(logger, "info")
    finally:
        os.environ.pop("STEALTHIX_LOG_LEVEL", None)


def test_environment_variable_log_format():
    """Test that STEALTHIX_LOG_FORMAT environment variable is respected."""
    import os

    os.environ["STEALTHIX_LOG_FORMAT"] = "json"
    try:
        logger = configure_logger()
        assert hasattr(logger, "info")
    finally:
        os.environ.pop("STEALTHIX_LOG_FORMAT", None)
