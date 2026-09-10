from __future__ import annotations

from typing import Any


def cli(argv: list[str] | None = None) -> int:
    from stealthix_headless_cli.main import cli as main_cli

    return main_cli(argv)


__all__ = ["cli"]
