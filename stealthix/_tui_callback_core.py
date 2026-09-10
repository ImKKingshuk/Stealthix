from __future__ import annotations

from typing import Any

from stealthix._tui_callback_runtime import (
    SUPPORTED_DBMS,
    SUPPORTED_METHODS,
    SUPPORTED_REPORT_FORMATS,
    config_from_tui_params,
    ok_response,
    session_from_payload,
    session_to_dict,
)
from stealthix.core.profiles import list_profiles, load_profile, save_profile
from stealthix.core.session import ScanSession
from stealthix.support_matrix import build_support_matrix
from stealthix.utils.payloads import load_payloads


def handle_core_action(
    action: str,
    params: dict[str, Any],
    *,
    initial_config: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    if action == "app.init":
        return ok_response(
            "Stealthix Rust TUI ready.",
            data={
                "dbms": SUPPORTED_DBMS,
                "methods": SUPPORTED_METHODS,
                "profiles": list_profiles(),
                "report_formats": SUPPORTED_REPORT_FORMATS,
                "crawl_defaults": {
                    "depth": 2,
                    "max_pages": 50,
                    "scope": "host",
                    "parse_robots": True,
                    "parse_sitemap": True,
                },
                "auth_types": [
                    "bearer",
                    "jwt",
                    "token",
                    "basic",
                    "digest",
                    "ntlm",
                    "form",
                    "script",
                ],
                "auth_defaults": {
                    "header_name": "Authorization",
                    "scheme": "Bearer",
                    "refresh_method": "POST",
                    "refresh_body_format": "json",
                },
                "api_schema_formats": ["auto", "openapi", "postman"],
                "api_defaults": {"method": "GET", "body_format": "json"},
                "websocket_defaults": {"timeout": 10.0, "message_format": "json"},
                "tamper_defaults": {"auto": True, "retry_budget": 3},
                "support_matrix": build_support_matrix(),
                "payload_families": ["sqli", "nosqli", "newsql"],
                "default_payloads": {
                    "sqli": load_payloads("sqli"),
                    "nosqli": load_payloads("nosqli"),
                    "newsql": load_payloads("newsql"),
                },
                "initial_config": initial_config,
            },
        )
    if action == "dbms.list_supported":
        return ok_response(data=SUPPORTED_DBMS)
    if action == "dbms.describe_supported":
        return ok_response(data=build_support_matrix())
    if action == "profile.list":
        return ok_response(data=list_profiles())
    if action == "profile.load":
        name = str(params.get("name") or "").strip()
        config, metadata = load_profile(name)
        return ok_response(
            f"Loaded profile '{name}'.",
            data={"config": config.to_dict(), "metadata": metadata},
        )
    if action == "profile.save":
        name = str(params.get("name") or "").strip()
        config = config_from_tui_params(params)
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        path = save_profile(name, config, metadata)
        return ok_response(f"Saved profile '{name}' to {path}.")
    if action == "session.load":
        path = str(params.get("path") or "").strip()
        session = ScanSession.load(path)
        return ok_response(f"Loaded session from {path}.", data=session_to_dict(session))
    if action == "session.save":
        path = str(params.get("path") or "").strip()
        payload = params.get("session") if isinstance(params.get("session"), dict) else None
        if payload is not None:
            session = session_from_payload(payload)
        else:
            metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
            metadata = metadata if isinstance(metadata, dict) else {}
            session = ScanSession(
                config=config_from_tui_params(params),
                metadata=metadata,
            )
        session.save(path)
        return ok_response(f"Saved session to {path}.", data={"path": path})
    return None
