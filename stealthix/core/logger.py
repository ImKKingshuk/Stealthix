from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable
from contextlib import contextmanager
from typing import Any

import structlog
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


def configure_logger(
    level: str = "INFO",
    log_format: str = "rich",
    log_file: str | None = None,
) -> structlog.stdlib.BoundLogger:
    """Configure structured logging with structlog.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR)
        log_format: Output format - 'rich' for console, 'json' for JSON
        log_file: Optional file path for JSON log output

    Returns:
        Configured structlog logger
    """
    # Get log level from environment if not specified
    if not level:
        level = os.getenv("STEALTHIX_LOG_LEVEL", "INFO")

    # Get log format from environment if not specified
    if not log_format:
        log_format = os.getenv("STEALTHIX_LOG_FORMAT", "rich")

    # Get log file from environment if not specified
    if not log_file:
        log_file = os.getenv("STEALTHIX_LOG_FILE")

    # Configure stdlib logging as the base
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True)],
    )

    # Configure structlog
    if log_format == "json" or log_file:
        # JSON configuration for file output or when explicitly requested
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            structlog.processors.JSONRenderer(),
        ]
    else:
        # Rich console configuration
        processors = [
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="%H:%M:%S"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.UnicodeDecoder(),
            structlog.dev.ConsoleRenderer(colors=True),
        ]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Add file handler if log_file is specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(level)
        logging.getLogger("stealthix").addHandler(file_handler)

    return structlog.get_logger("stealthix")


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    """Get a structured logger for a module.

    Args:
        name: Module name (defaults to caller's module)

    Returns:
        Structlog bound logger
    """
    if name is None:
        name = "stealthix"
    return structlog.get_logger(name)


def get_console() -> Console:
    return Console()


def get_progress() -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TimeElapsedColumn(),
    )


@contextmanager
def bind_context(**context: Any):
    """Temporarily bind context to the current logger.

    Args:
        **context: Key-value pairs to bind to logger context

    Yields:
        None
    """
    logger = structlog.get_logger()
    original_context = logger._context.copy()
    logger = logger.bind(**context)
    try:
        yield logger
    finally:
        logger._context.clear()
        logger._context.update(original_context)


def set_module_log_level(module: str, level: str) -> None:
    """Set log level for a specific module.

    Args:
        module: Module name (e.g., "stealthix.core.engine")
        level: Log level (DEBUG, INFO, WARNING, ERROR)
    """
    logging.getLogger(module).setLevel(level)
