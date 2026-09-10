from __future__ import annotations

import json
from typing import Any

from stealthix.core.session import SessionConfig
from stealthix.detection.rest_api import infer_api_base_url


def _split_blob(blob: str | None) -> list[str]:
    if not blob:
        return []
    return [part.strip() for part in blob.replace("\n", ";").split(";") if part.strip()]


def parse_mapping(blob: str | None, *, separators: tuple[str, ...] = (":", "=")) -> dict[str, str]:
    items: dict[str, str] = {}
    for part in _split_blob(blob):
        for sep in separators:
            if sep in part:
                key, value = part.split(sep, 1)
                if key.strip():
                    items[key.strip()] = value.strip()
                break
    return items


def parse_target_params(blob: str | None) -> list[str] | None:
    if not blob:
        return None
    items = [piece.strip() for piece in blob.replace("\n", ",").split(",") if piece.strip()]
    return items or None


def parse_list(value: Any, *, separators: tuple[str, ...] = (",", "\n", ";")) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, list):
        items = [str(item).strip() for item in value if str(item).strip()]
        return items or None
    text = str(value)
    for separator in separators[1:]:
        text = text.replace(separator, separators[0])
    items = [piece.strip() for piece in text.split(separators[0]) if piece.strip()]
    return items or None


def parse_body(blob: str | None, body_format: str) -> dict[str, Any] | None:
    if not blob or not blob.strip():
        return None
    raw = blob.strip()
    if body_format == "json":
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"payload": parsed}
        except json.JSONDecodeError:
            return {"payload": raw}
    mapping = parse_mapping(raw, separators=("=", ":"))
    return mapping or {"payload": raw}


def parse_custom_payloads(payload: Any) -> dict[str, list[str]] | None:
    if not isinstance(payload, dict):
        return None
    parsed: dict[str, list[str]] = {}
    for family, items in payload.items():
        key = str(family).strip().lower()
        if not key:
            continue
        if isinstance(items, str):
            values = [line.strip() for line in items.splitlines() if line.strip()]
        elif isinstance(items, list):
            values = [str(item).strip() for item in items if str(item).strip()]
        else:
            continue
        if values:
            parsed[key] = values
    return parsed or None


def _positive_int(value: Any, default: int) -> int:
    try:
        if value is None or str(value).strip() == "":
            return default
        return max(1, int(value))
    except (TypeError, ValueError):
        return default


def config_from_tui_params(params: dict[str, Any]) -> SessionConfig:
    source = params.get("config") if isinstance(params.get("config"), dict) else {}
    source = source if isinstance(source, dict) else {}
    body_format = str(source.get("body_format") or params.get("body_format") or "form").lower()
    base_url = str(
        source.get("url")
        or source.get("base_url")
        or params.get("url")
        or params.get("base_url")
        or ""
    ).strip()
    if not base_url and (source.get("api_schema") or params.get("api_schema")):
        base_url = (
            infer_api_base_url(
                str(source.get("api_schema") or params.get("api_schema")),
                schema_format=str(
                    source.get("api_schema_format") or params.get("api_schema_format") or "auto"
                ),
                fallback=str(source.get("api_base_url") or params.get("api_base_url") or "").strip()
                or None,
            )
            or ""
        )
    if not base_url and (source.get("ws_url") or params.get("ws_url")):
        base_url = str(source.get("ws_url") or params.get("ws_url") or "").strip()
    dbms = source.get("dbms")
    if isinstance(dbms, str) and dbms.strip().lower() == "auto":
        dbms = None
    technique = source.get("technique")
    if isinstance(technique, str) and not technique.strip():
        technique = None
    auth_source = source.get("auth") if isinstance(source.get("auth"), dict) else {}
    auth_source = auth_source if isinstance(auth_source, dict) else {}
    auth_config = (
        auth_source.get("auth_config") if isinstance(auth_source.get("auth_config"), dict) else {}
    )
    auth_config = auth_config if isinstance(auth_config, dict) else {}
    auth_extra_fields = parse_mapping(
        auth_source.get("auth_extra_fields") or auth_source.get("auth_extra_field"),
        separators=("=", ":"),
    )
    auth_refresh_body = parse_mapping(auth_source.get("auth_refresh_body"), separators=("=", ":"))
    for key, value in {
        "username": auth_source.get("auth_user")
        or auth_source.get("username")
        or params.get("auth_user")
        or params.get("username"),
        "password": auth_source.get("auth_pass")
        or auth_source.get("password")
        or params.get("auth_pass")
        or params.get("password"),
        "login_url": auth_source.get("auth_login_url")
        or auth_source.get("login_url")
        or params.get("auth_login_url")
        or params.get("login_url"),
        "username_field": auth_source.get("auth_user_field")
        or auth_source.get("username_field")
        or params.get("auth_user_field")
        or params.get("username_field"),
        "password_field": auth_source.get("auth_pass_field")
        or auth_source.get("password_field")
        or params.get("auth_pass_field")
        or params.get("password_field"),
        "refresh_url": auth_source.get("auth_refresh_url")
        or auth_source.get("refresh_url")
        or params.get("auth_refresh_url")
        or params.get("refresh_url"),
        "refresh_method": auth_source.get("auth_refresh_method")
        or auth_source.get("refresh_method")
        or params.get("auth_refresh_method")
        or params.get("refresh_method"),
        "refresh_body_format": auth_source.get("auth_refresh_body_format")
        or auth_source.get("refresh_body_format")
        or params.get("auth_refresh_body_format")
        or params.get("refresh_body_format"),
        "token_json_path": auth_source.get("auth_token_path")
        or auth_source.get("token_json_path")
        or params.get("auth_token_path")
        or params.get("token_json_path"),
        "header_name": auth_source.get("auth_header")
        or auth_source.get("header_name")
        or params.get("auth_header")
        or params.get("header_name"),
        "scheme": auth_source.get("auth_scheme")
        or auth_source.get("scheme")
        or params.get("auth_scheme")
        or params.get("scheme"),
        "script": auth_source.get("auth_script")
        or auth_source.get("script")
        or params.get("auth_script")
        or params.get("script"),
        "success_indicator": auth_source.get("auth_success_indicator")
        or auth_source.get("success_indicator")
        or params.get("auth_success_indicator")
        or params.get("success_indicator"),
        "failure_indicator": auth_source.get("auth_failure_indicator")
        or auth_source.get("failure_indicator")
        or params.get("auth_failure_indicator")
        or params.get("failure_indicator"),
        "verify_url": auth_source.get("auth_verify_url")
        or auth_source.get("verify_url")
        or params.get("auth_verify_url")
        or params.get("verify_url"),
        "csrf_url": auth_source.get("csrf_url") or params.get("csrf_url"),
        "csrf_field": auth_source.get("csrf_field") or params.get("csrf_field"),
    }.items():
        if value not in (None, ""):
            auth_config[str(key)] = value
    if auth_extra_fields:
        auth_config["extra_fields"] = auth_extra_fields
    if auth_refresh_body:
        auth_config["refresh_body"] = auth_refresh_body
    auth_token = (
        auth_source.get("auth_token")
        or auth_source.get("token")
        or params.get("auth_token")
        or params.get("token")
    )
    if auth_token not in (None, ""):
        auth_config["token"] = auth_token
    auth_type = auth_source.get("auth_type") or params.get("auth_type")
    if not auth_type and auth_token:
        auth_type = "bearer"
    ws_headers = parse_mapping(
        source.get("ws_headers")
        or source.get("ws_header")
        or params.get("ws_headers")
        or params.get("ws_header"),
        separators=(":", "="),
    )
    return SessionConfig(
        base_url=base_url,
        headers=parse_mapping(
            source.get("headers") or params.get("headers"), separators=(":", "=")
        ),
        cookies=parse_mapping(
            source.get("cookies") or params.get("cookies"), separators=("=", ":")
        ),
        proxy=str(source.get("proxy") or params.get("proxy")).strip()
        if source.get("proxy") or params.get("proxy")
        else None,
        verify_tls=bool(source.get("verify_tls") or params.get("verify_tls", True)),
        auth_token=str(auth_token).strip() if auth_token not in (None, "") else None,
        auth_type=str(auth_type).strip().lower()
        if isinstance(auth_type, str) and auth_type.strip()
        else None,
        auth_config=auth_config or None,
        method=str(source.get("method") or params.get("method") or "GET").upper(),
        data=parse_body(source.get("body") or params.get("body"), body_format),
        body_format=body_format,
        target_params=parse_target_params(
            source.get("target_params") or params.get("target_params")
        ),
        custom_payloads=parse_custom_payloads(
            source.get("custom_payloads") or params.get("custom_payloads")
        ),
        technique=str(technique).strip()
        if isinstance(technique, str) and technique.strip()
        else None,
        dbms=str(dbms).strip() if isinstance(dbms, str) and dbms else None,
        risk=int(source.get("risk") or params.get("risk", 1)),
        level=int(source.get("level") or params.get("level", 1)),
        threads=_positive_int(source.get("threads") or params.get("threads"), 5),
        api_schema=str(source.get("api_schema") or params.get("api_schema") or "").strip() or None,
        api_schema_format=str(
            source.get("api_schema_format") or params.get("api_schema_format") or "auto"
        ).lower(),
        api_base_url=str(source.get("api_base_url") or params.get("api_base_url") or "").strip()
        or None,
        api_header_params=parse_list(
            source.get("api_header_params")
            or source.get("api_header_param")
            or params.get("api_header_params")
            or params.get("api_header_param")
        ),
        ws_url=str(source.get("ws_url") or params.get("ws_url") or "").strip() or None,
        ws_messages=parse_list(
            source.get("ws_messages")
            or source.get("ws_message")
            or params.get("ws_messages")
            or params.get("ws_message")
        ),
        ws_headers=ws_headers or None,
        ws_subprotocols=parse_list(
            source.get("ws_subprotocols")
            or source.get("ws_subprotocol")
            or params.get("ws_subprotocols")
            or params.get("ws_subprotocol")
        ),
        ws_timeout=float(source.get("ws_timeout") or params.get("ws_timeout", 10.0) or 10.0),
        tamper_pipeline=parse_list(source.get("tamper_pipeline") or source.get("tamper")),
        tamper_auto=bool(source.get("tamper_auto", True)),
        tamper_retry_budget=_positive_int(source.get("tamper_retry_budget"), 3),
    )
