from __future__ import annotations

from collections.abc import Callable
from typing import Any

from stealthix._tui_callback_core import handle_core_action
from stealthix._tui_callback_extract import handle_extract_action
from stealthix._tui_callback_proxy import handle_proxy_action
from stealthix._tui_callback_reports import handle_report_action
from stealthix._tui_callback_runtime import error_response
from stealthix._tui_callback_scan import handle_scan_action


def build_tui_callback(
    *,
    initial_config: dict[str, Any] | None = None,
) -> Callable[[str, dict[str, Any]], dict[str, Any]]:
    handlers = [
        handle_scan_action,
        handle_extract_action,
        handle_proxy_action,
        handle_report_action,
    ]

    def callback(action: str, params: dict[str, Any] | None) -> dict[str, Any]:
        safe_params = params if isinstance(params, dict) else {}
        try:
            result = handle_core_action(action, safe_params, initial_config=initial_config)
            if result is not None:
                return result
            for handler in handlers:
                result = handler(action, safe_params)
                if result is not None:
                    return result
            return error_response(f"unsupported action: {action}")
        except Exception as exc:  # pragma: no cover - exercised through public callback tests
            return error_response(str(exc), message=f"Action failed: {action}")

    return callback


__all__ = ["build_tui_callback"]
