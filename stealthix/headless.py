from __future__ import annotations

import datetime
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from stealthix.config import load_config
from stealthix.core.checkpoint import CheckpointManager, load_checkpoint, restore_session
from stealthix.core.engine import Engine
from stealthix.core.logger import configure_logger
from stealthix.core.models import ScanResult
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.crawler import Spider
from stealthix.detection.rest_api import infer_api_base_url
from stealthix.distributed import ScanCoordinator, run_worker
from stealthix.extraction import (
    dump_table,
    enumerate_columns,
    enumerate_databases,
    enumerate_tables,
    execute_command,
    extract_hashes,
    read_file,
)
from stealthix.impact import (
    FILE_READ,
    FILE_WRITE,
    OS_COMMAND,
    UDF_DROPPER,
    ImpactExecutionOptions,
    SessionImpactExecutor,
    build_capability_matrix,
    plan_impact_operation,
)
from stealthix.plugins.runtime import apply_plugin
from stealthix.proxy import ProxyWorkspace, passive_injection_hints
from stealthix.reporting import (
    render_csv,
    render_html,
    render_json,
    render_junit,
    render_markdown,
    render_pdf,
    render_sarif,
)
from stealthix.support_matrix import (
    build_support_matrix,
    ensure_extraction_supported,
    get_support_entry,
    render_support_matrix_markdown,
    render_support_matrix_text,
)
from stealthix.templates import (
    TemplateResponse,
    evaluate_template,
    load_stealthix_template,
    request_specs_for_template,
)
from stealthix.workflows import (
    RequestSpec,
    expand_payload_positions,
    import_curl,
    import_har,
    import_raw_http,
)
from stealthix_headless_cli.commands import (
    crawl_options_from_args,
    format_recon_output,
    load_url_file,
    recon_endpoints,
    recon_tech,
)


class HeadlessUsageError(ValueError):
    pass


@dataclass
class HeadlessResult:
    exit_code: int
    rendered: str | bytes
    is_binary: bool = False


def initialize_runtime(config_path: str | None, log_level: str):
    logger = configure_logger(log_level)
    config_data = load_config(config_path) if config_path else {}
    return logger, config_data


def emit_result(result: HeadlessResult, output: str | None) -> None:
    if output:
        path = Path(output)
        if result.is_binary:
            path.write_bytes(
                result.rendered
                if isinstance(result.rendered, bytes)
                else result.rendered.encode("latin1")
            )
        else:
            path.write_text(str(result.rendered), encoding="utf-8")
        return
    if result.is_binary:
        print(
            (
                result.rendered
                if isinstance(result.rendered, bytes)
                else str(result.rendered).encode()
            ).decode("latin1")
        )
    else:
        print(result.rendered)


def _parse_headers(values: list[str]) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        if ":" not in item:
            continue
        key, value = item.split(":", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def _parse_key_value_pairs(
    values: list[str], *, separators: tuple[str, ...] = (":", "=")
) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for item in values:
        for separator in separators:
            if separator in item:
                key, value = item.split(separator, 1)
                if key.strip():
                    parsed[key.strip()] = value.strip()
                break
    return parsed


def _option(
    args: Any, config_data: dict[str, Any], name: str, *, loaded: Any = None, default: Any = None
) -> Any:
    arg_value = getattr(args, name, None)
    if name in config_data:
        return config_data[name]
    if arg_value not in (None, "", []):
        if loaded is None or arg_value != default:
            return arg_value
    if loaded not in (None, "", []):
        return loaded
    return default if arg_value in (None, "", []) else arg_value


def _build_auth_config(
    args: Any, config_data: dict[str, Any], loaded_session: ScanSession | None
) -> tuple[str | None, str | None, dict[str, Any] | None]:
    loaded_config = loaded_session.config if loaded_session else None
    auth_config = (
        dict(loaded_config.auth_config or {})
        if loaded_config and isinstance(loaded_config.auth_config, dict)
        else {}
    )
    if isinstance(config_data.get("auth_config"), dict):
        auth_config.update(config_data["auth_config"])

    auth_type = _option(
        args,
        config_data,
        "auth_type",
        loaded=getattr(loaded_config, "auth_type", None),
        default=None,
    )
    auth_token = _option(
        args,
        config_data,
        "auth_token",
        loaded=getattr(loaded_config, "auth_token", None),
        default=None,
    )

    mappings = {
        "username": _option(
            args, config_data, "auth_user", loaded=auth_config.get("username"), default=None
        ),
        "password": _option(
            args, config_data, "auth_pass", loaded=auth_config.get("password"), default=None
        ),
        "login_url": _option(
            args, config_data, "auth_login_url", loaded=auth_config.get("login_url"), default=None
        ),
        "username_field": _option(
            args,
            config_data,
            "auth_user_field",
            loaded=auth_config.get("username_field"),
            default=None,
        ),
        "password_field": _option(
            args,
            config_data,
            "auth_pass_field",
            loaded=auth_config.get("password_field"),
            default=None,
        ),
        "refresh_url": _option(
            args,
            config_data,
            "auth_refresh_url",
            loaded=auth_config.get("refresh_url"),
            default=None,
        ),
        "refresh_method": _option(
            args,
            config_data,
            "auth_refresh_method",
            loaded=auth_config.get("refresh_method"),
            default="POST",
        ),
        "refresh_body_format": _option(
            args,
            config_data,
            "auth_refresh_body_format",
            loaded=auth_config.get("refresh_body_format"),
            default="json",
        ),
        "token_json_path": _option(
            args,
            config_data,
            "auth_token_path",
            loaded=auth_config.get("token_json_path"),
            default=None,
        ),
        "header_name": _option(
            args,
            config_data,
            "auth_header",
            loaded=auth_config.get("header_name"),
            default="Authorization",
        ),
        "scheme": _option(
            args, config_data, "auth_scheme", loaded=auth_config.get("scheme"), default="Bearer"
        ),
        "script": _option(
            args, config_data, "auth_script", loaded=auth_config.get("script"), default=None
        ),
        "success_indicator": _option(
            args,
            config_data,
            "auth_success_indicator",
            loaded=auth_config.get("success_indicator"),
            default=None,
        ),
        "failure_indicator": _option(
            args,
            config_data,
            "auth_failure_indicator",
            loaded=auth_config.get("failure_indicator"),
            default=None,
        ),
        "verify_url": _option(
            args, config_data, "auth_verify_url", loaded=auth_config.get("verify_url"), default=None
        ),
        "csrf_url": _option(
            args, config_data, "csrf_url", loaded=auth_config.get("csrf_url"), default=None
        ),
        "csrf_field": _option(
            args, config_data, "csrf_field", loaded=auth_config.get("csrf_field"), default=None
        ),
    }
    auth_config.update({key: value for key, value in mappings.items() if value not in (None, "")})

    extra_fields = _parse_key_value_pairs(
        getattr(args, "auth_extra_field", []) or [], separators=("=", ":")
    )
    if not extra_fields and isinstance(auth_config.get("extra_fields"), dict):
        extra_fields = {str(key): str(value) for key, value in auth_config["extra_fields"].items()}
    if extra_fields:
        auth_config["extra_fields"] = extra_fields

    refresh_body = _parse_key_value_pairs(
        getattr(args, "auth_refresh_body", []) or [], separators=("=", ":")
    )
    if not refresh_body and isinstance(auth_config.get("refresh_body"), dict):
        refresh_body = {str(key): value for key, value in auth_config["refresh_body"].items()}
    if refresh_body:
        auth_config["refresh_body"] = refresh_body

    if auth_token:
        auth_config["token"] = auth_token
    if not auth_type and auth_token:
        auth_type = "bearer"
    return auth_type, auth_token, (auth_config or None)


def build_session(args: Any, config_data: dict[str, Any]) -> ScanSession:
    session_load = getattr(args, "session_load", None) or config_data.get("session_load")
    loaded_session = ScanSession.load(session_load) if session_load else None
    loaded_config = loaded_session.config if loaded_session else None
    headers = dict(loaded_config.headers) if loaded_config else {}
    cookies = dict(loaded_config.cookies) if loaded_config else {}
    headers.update(config_data.get("headers", {}))
    cookies.update(config_data.get("cookies", {}))
    headers.update(_parse_headers(getattr(args, "header", [])))
    cookies.update(_parse_headers(getattr(args, "cookie", [])))
    auth_type, auth_token, auth_config = _build_auth_config(args, config_data, loaded_session)
    api_schema = _option(
        args,
        config_data,
        "api_schema",
        loaded=getattr(loaded_config, "api_schema", None),
        default=None,
    )
    api_schema_format = _option(
        args,
        config_data,
        "api_schema_format",
        loaded=getattr(loaded_config, "api_schema_format", None),
        default="auto",
    )
    api_base_url = _option(
        args,
        config_data,
        "api_base_url",
        loaded=getattr(loaded_config, "api_base_url", None),
        default=None,
    )
    ws_url = _option(
        args, config_data, "ws_url", loaded=getattr(loaded_config, "ws_url", None), default=None
    )
    base_url = _option(
        args, config_data, "url", loaded=getattr(loaded_config, "base_url", None), default=None
    )
    if not base_url and api_schema:
        base_url = api_base_url or infer_api_base_url(
            str(api_schema), schema_format=str(api_schema_format or "auto"), fallback=None
        )
    if not base_url and ws_url:
        base_url = ws_url
    if not base_url:
        raise HeadlessUsageError("Target URL is required.")
    session_config = SessionConfig(
        base_url=base_url,
        headers=headers,
        cookies=cookies,
        proxy=_option(
            args, config_data, "proxy", loaded=getattr(loaded_config, "proxy", None), default=None
        ),
        timeout=float(
            _option(
                args,
                config_data,
                "timeout",
                loaded=getattr(loaded_config, "timeout", None),
                default=20.0,
            )
        ),
        verify_tls=bool(
            _option(
                args,
                config_data,
                "verify_tls",
                loaded=getattr(loaded_config, "verify_tls", None),
                default=True,
            )
        ),
        auth_token=auth_token,
        auth_type=auth_type,
        auth_config=auth_config,
        method=_option(
            args,
            config_data,
            "method",
            loaded=getattr(loaded_config, "method", None),
            default="GET",
        ),
        data=config_data.get("data", getattr(loaded_config, "data", None)),
        body_format=config_data.get("body_format", getattr(loaded_config, "body_format", "form")),
        target_params=(getattr(args, "param", []) or None)
        or config_data.get("target_params")
        or getattr(loaded_config, "target_params", None),
        custom_payloads=config_data.get(
            "custom_payloads", getattr(loaded_config, "custom_payloads", None)
        ),
        technique=_option(
            args,
            config_data,
            "technique",
            loaded=getattr(loaded_config, "technique", None),
            default=None,
        ),
        dbms=_option(
            args, config_data, "dbms", loaded=getattr(loaded_config, "dbms", None), default=None
        ),
        risk=int(
            _option(
                args, config_data, "risk", loaded=getattr(loaded_config, "risk", None), default=1
            )
        ),
        level=int(
            _option(
                args, config_data, "level", loaded=getattr(loaded_config, "level", None), default=1
            )
        ),
        batch=bool(
            _option(
                args,
                config_data,
                "batch",
                loaded=getattr(loaded_config, "batch", None),
                default=False,
            )
        ),
        threads=max(
            1,
            int(
                _option(
                    args,
                    config_data,
                    "threads",
                    loaded=getattr(loaded_config, "threads", None),
                    default=5,
                )
            ),
        ),
        pool_connections=(
            max(1, int(config_data["pool_connections"]))
            if config_data.get("pool_connections") is not None
            else getattr(loaded_config, "pool_connections", None)
        ),
        pool_maxsize=(
            max(1, int(config_data["pool_maxsize"]))
            if config_data.get("pool_maxsize") is not None
            else getattr(loaded_config, "pool_maxsize", None)
        ),
        api_schema=str(api_schema).strip() if api_schema else None,
        api_schema_format=str(api_schema_format or "auto").lower() if api_schema_format else "auto",
        api_base_url=str(api_base_url).strip() if api_base_url else None,
        api_header_params=(getattr(args, "api_header_param", []) or None)
        or config_data.get("api_header_params")
        or getattr(loaded_config, "api_header_params", None),
        ws_url=str(ws_url).strip() if ws_url else None,
        ws_messages=(getattr(args, "ws_message", []) or None)
        or config_data.get("ws_messages")
        or getattr(loaded_config, "ws_messages", None),
        ws_headers=_parse_headers(getattr(args, "ws_header", []))
        or config_data.get("ws_headers")
        or getattr(loaded_config, "ws_headers", None),
        ws_subprotocols=(getattr(args, "ws_subprotocol", []) or None)
        or config_data.get("ws_subprotocols")
        or getattr(loaded_config, "ws_subprotocols", None),
        ws_timeout=float(
            _option(
                args,
                config_data,
                "ws_timeout",
                loaded=getattr(loaded_config, "ws_timeout", None),
                default=10.0,
            )
        ),
        tamper_pipeline=(getattr(args, "tamper", []) or None)
        or config_data.get("tamper_pipeline")
        or getattr(loaded_config, "tamper_pipeline", None),
        tamper_auto=bool(
            _option(
                args,
                config_data,
                "tamper_auto",
                loaded=getattr(loaded_config, "tamper_auto", None),
                default=True,
            )
        ),
        tamper_retry_budget=max(
            1,
            int(
                _option(
                    args,
                    config_data,
                    "tamper_retry_budget",
                    loaded=getattr(loaded_config, "tamper_retry_budget", None),
                    default=3,
                )
            ),
        ),
    )
    if getattr(args, "test_all_params", False):
        session_config.target_params = None
    metadata = dict(loaded_session.metadata) if loaded_session else {}
    metadata.update(config_data)
    session = ScanSession(session_config, metadata=metadata)
    if loaded_session is not None:
        session.history = loaded_session.history
        session.creds = loaded_session.creds
    if auth_config:
        for key in ("username", "password", "token"):
            value = auth_config.get(key)
            if value not in (None, ""):
                session.creds.add("auth_token" if key == "token" else key, str(value))
    return session


def apply_wizard(args: Any) -> None:
    if not getattr(args, "wizard", False) or getattr(args, "batch", False):
        return
    if not getattr(args, "url", None):
        args.url = input("Target URL: ").strip()
    if not getattr(args, "dbms", None):
        args.dbms = input("DBMS (leave empty for auto): ").strip() or None
    if not getattr(args, "technique", None):
        args.technique = input("Technique (B/E/U/T/S or leave empty): ").strip() or None


def require_url(args: Any) -> None:
    if not getattr(args, "url", None):
        raise HeadlessUsageError("Target URL is required.")


def _save_session_if_requested(args: Any, session: ScanSession) -> None:
    session_save = getattr(args, "session_save", None)
    if not session_save:
        return
    path = Path(session_save)
    path.parent.mkdir(parents=True, exist_ok=True)
    session.save(str(path))


def _checkpoint_settings(
    args: Any, config_data: dict[str, Any], *, resume_path: str | None = None
) -> tuple[Path | None, float]:
    configured = (
        getattr(args, "checkpoint_file", None) or config_data.get("checkpoint_file") or resume_path
    )
    interval = float(
        config_data.get("checkpoint_interval", getattr(args, "checkpoint_interval", 0.0)) or 0.0
    )
    if not configured and interval > 0:
        configured = "stealthix-checkpoint.stx"
    return (Path(configured) if configured else None), max(0.0, interval)


def _enable_checkpointing(
    session: ScanSession,
    *,
    path: Path | None,
    interval: float,
    resume_payload: dict[str, Any] | None = None,
) -> CheckpointManager | None:
    if path is None:
        return None
    manager = CheckpointManager(path=path, interval_seconds=interval)
    session.runtime["checkpoint_manager"] = manager
    if resume_payload is not None:
        session.runtime["checkpoint_resume_payload"] = resume_payload
        previous = (
            resume_payload.get("state") if isinstance(resume_payload.get("state"), dict) else None
        )
        session.runtime["checkpoint_resume_count"] = (
            int(previous.get("resume_count", 0) if previous else 0) + 1
        )
    session.metadata.setdefault("checkpoint", {}).update(
        {
            "enabled": True,
            "path": str(path),
            "interval_seconds": interval,
            "resumed": resume_payload is not None,
        }
    )
    return manager


def _ci_metadata(exit_code: int) -> dict[str, Any]:
    meaning = "clean" if exit_code == 0 else "findings" if exit_code == 1 else "error"
    return {
        "exit_code": int(exit_code),
        "semantic": meaning,
        "convention": {"0": "clean", "1": "findings", "2": "error"},
    }


def _require_extraction_support(dbms: str | None, operation: str) -> None:
    try:
        ensure_extraction_supported(dbms, operation)
    except ValueError as exc:
        raise HeadlessUsageError(str(exc)) from exc


def run_scan(args: Any, logger: Any, config_data: dict[str, Any]) -> HeadlessResult:
    resume_path = getattr(args, "resume", None) or config_data.get("resume")
    if resume_path and (getattr(args, "session_load", None) or config_data.get("session_load")):
        raise HeadlessUsageError("Use either --resume or --session-load, not both.")

    file_urls: list[Any] = []
    checkpoint_mode = "detect"
    checkpoint_input: dict[str, Any] = {}
    resume_payload: dict[str, Any] | None = None

    if resume_path:
        resume_payload = load_checkpoint(resume_path)
        session = restore_session(resume_payload["session"])
        checkpoint_mode = str(resume_payload.get("mode") or "detect")
        checkpoint_input = dict(resume_payload.get("input_context") or {})
        logger.info("Resuming %s scan from checkpoint %s", checkpoint_mode, resume_path)
    else:
        apply_wizard(args)
        file_urls = load_url_file(getattr(args, "url_file", None))
        if not file_urls and not (
            getattr(args, "session_load", None) or config_data.get("session_load")
        ):
            if not (
                getattr(args, "api_schema", None)
                or config_data.get("api_schema")
                or getattr(args, "ws_url", None)
                or config_data.get("ws_url")
            ):
                require_url(args)
        elif file_urls and not getattr(args, "url", None):
            args.url = file_urls[0]
        session = build_session(args, config_data)
        if file_urls:
            checkpoint_mode = "scan_list"
            checkpoint_input = {"specs": list(file_urls)}
        elif getattr(args, "crawl", False):
            checkpoint_mode = "scan_site"
            crawl_options = crawl_options_from_args(args)
            checkpoint_input = {
                "crawl_options": {
                    "depth": crawl_options.max_depth,
                    "max_pages": crawl_options.max_pages,
                    "scope": crawl_options.scope,
                    "parse_robots": crawl_options.parse_robots,
                    "parse_sitemap": crawl_options.parse_sitemap,
                }
            }

    checkpoint_path, checkpoint_interval = _checkpoint_settings(
        args, config_data, resume_path=resume_path
    )
    checkpoint_manager = _enable_checkpointing(
        session,
        path=checkpoint_path,
        interval=checkpoint_interval,
        resume_payload=resume_payload,
    )
    try:
        engine = Engine(session)
        if checkpoint_mode == "scan_list":
            result = engine.scan_list(checkpoint_input.get("specs") or file_urls)
        elif checkpoint_mode == "scan_site":
            crawl_options = crawl_options_from_args(args)
            if isinstance(checkpoint_input.get("crawl_options"), dict):
                crawl_options.max_depth = int(
                    checkpoint_input["crawl_options"].get("depth", crawl_options.max_depth)
                )
                crawl_options.max_pages = int(
                    checkpoint_input["crawl_options"].get("max_pages", crawl_options.max_pages)
                )
                crawl_options.scope = str(
                    checkpoint_input["crawl_options"].get("scope", crawl_options.scope)
                )
                crawl_options.parse_robots = bool(
                    checkpoint_input["crawl_options"].get(
                        "parse_robots", crawl_options.parse_robots
                    )
                )
                crawl_options.parse_sitemap = bool(
                    checkpoint_input["crawl_options"].get(
                        "parse_sitemap", crawl_options.parse_sitemap
                    )
                )
            result = engine.scan_site(
                session.config.base_url,
                depth=crawl_options.max_depth,
                max_pages=crawl_options.max_pages,
                scope=crawl_options.scope,
                parse_robots=crawl_options.parse_robots,
                parse_sitemap=crawl_options.parse_sitemap,
            )
        else:
            result = engine.detect()
    except Exception as exc:
        if checkpoint_manager is not None:
            checkpoint_manager.save_snapshot(
                session,
                mode=checkpoint_mode,
                status="error",
                state=dict(session.runtime.get("checkpoint_last_state") or {}),
                input_context=checkpoint_input,
                error={"type": type(exc).__name__, "message": str(exc)},
                force=True,
            )
            session.metadata.setdefault("checkpoint", {})["status"] = "error"
        logger.exception("Scan failed: %s", exc)
        return HeadlessResult(exit_code=2, rendered="")
    logger.info("Findings: %s", len(result.findings))
    result.metadata["generated_at"] = datetime.datetime.now(datetime.UTC).isoformat()
    result.metadata.setdefault("request_history", session.history.to_list())
    result.metadata.setdefault("scanned_targets", [result.target])
    result.metadata["ci"] = _ci_metadata(1 if result.findings else 0)
    if checkpoint_manager is not None:
        result.metadata.setdefault("checkpoint", {}).update(
            {
                "enabled": True,
                "path": str(checkpoint_manager.path),
                "interval_seconds": checkpoint_manager.interval_seconds,
                "resumed": resume_payload is not None,
                "status": "completed",
                "mode": checkpoint_mode,
            }
        )
    session.metadata.update(result.metadata)
    _save_session_if_requested(args, session)
    report = getattr(args, "report", "json")
    return render_report(result, report)


def render_report(result: ScanResult, report: str) -> HeadlessResult:
    if report == "html":
        rendered = render_html(result)
    elif report == "markdown":
        rendered = render_markdown(result)
    elif report == "pdf":
        rendered = render_pdf(result)
    elif report == "sarif":
        rendered = render_sarif(result)
    elif report == "junit":
        rendered = render_junit(result)
    elif report == "csv":
        rendered = render_csv(result)
    else:
        rendered = render_json(result)
    return HeadlessResult(
        exit_code=1 if result.findings else 0, rendered=rendered, is_binary=report == "pdf"
    )


def run_distributed_scan(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    """Run distributed scan using Redis task queue."""
    if getattr(args, "worker_mode", False):
        # Run as worker process
        redis_host = getattr(args, "redis_host", "localhost")
        redis_port = getattr(args, "redis_port", 6379)
        run_worker(redis_host=redis_host, redis_port=redis_port)
        return HeadlessResult(exit_code=0, rendered="Worker mode completed")

    # Run as coordinator
    targets = []
    if getattr(args, "url", None):
        targets.append(args.url)
    if getattr(args, "url_file", None):
        targets.extend(load_url_file(args.url_file))

    if not targets:
        raise HeadlessUsageError("Distributed mode requires --url or --url-file")

    redis_host = getattr(args, "redis_host", "localhost")
    redis_port = getattr(args, "redis_port", 6379)
    chunk_size = getattr(args, "chunk_size", 25)

    # Build scan config from args
    scan_config = {
        "risk": getattr(args, "risk", 2),
        "dbms": getattr(args, "dbms", None),
        "plugins": getattr(args, "plugins", None),
        "auth_type": getattr(args, "auth_type", None),
        "auth_token": getattr(args, "auth_token", None),
        "auth_user": getattr(args, "auth_user", None),
        "auth_password": getattr(args, "auth_password", None),
    }

    coordinator = ScanCoordinator(
        redis_host=redis_host,
        redis_port=redis_port,
        chunk_size=chunk_size,
    )

    try:
        coordinator.distribute_scan(targets, scan_config)
        result = coordinator.wait_for_completion()
        report = getattr(args, "report", "json")
        return render_report(result, report)
    except Exception as e:
        return HeadlessResult(exit_code=1, rendered=f"Distributed scan failed: {e}")
    finally:
        coordinator.queue.disconnect()


def run_worker_mode(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    """Run as a worker process for distributed scanning."""
    redis_host = getattr(args, "redis_host", "localhost")
    redis_port = getattr(args, "redis_port", 6379)
    run_worker(redis_host=redis_host, redis_port=redis_port)
    return HeadlessResult(exit_code=0, rendered="Worker mode completed")


def run_crawl(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    if not (
        getattr(args, "url", None)
        or getattr(args, "session_load", None)
        or config_data.get("session_load")
    ):
        require_url(args)
    session = build_session(args, config_data)
    options = crawl_options_from_args(args, prefix="")
    result = Spider(session, options=options).crawl(session.config.base_url)
    session.metadata["crawl"] = result
    _save_session_if_requested(args, session)
    return HeadlessResult(exit_code=0, rendered=json.dumps(result, indent=2, sort_keys=True))


def run_extract(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    if not (
        getattr(args, "url", None)
        or getattr(args, "session_load", None)
        or config_data.get("session_load")
    ):
        require_url(args)
    session = build_session(args, config_data)
    apply_plugin(session)
    action = getattr(args, "extract_action", None)
    if action == "enum_dbs":
        _require_extraction_support(session.config.dbms, "databases")
        result = enumerate_databases(session)
    elif action == "enum_tables":
        _require_extraction_support(session.config.dbms, "tables")
        if not getattr(args, "database", None):
            raise HeadlessUsageError("enum-tables requires -D/--database")
        result = enumerate_tables(session, args.database)
    elif action == "enum_columns":
        _require_extraction_support(session.config.dbms, "columns")
        if not getattr(args, "table", None):
            raise HeadlessUsageError("enum-columns requires -T/--table")
        result = enumerate_columns(session, args.table)
    elif action == "dump":
        _require_extraction_support(session.config.dbms, "dump")
        if not getattr(args, "table", None):
            raise HeadlessUsageError("dump requires -T/--table")
        columns = list(getattr(args, "column", []) or [])
        if not columns:
            raise HeadlessUsageError("dump requires at least one -C/--column")
        table = (
            args.table
            if not getattr(args, "database", None) or "." in args.table
            else f"{args.database}.{args.table}"
        )
        result = dump_table(session, table, columns)
    elif action == "read_file":
        _require_extraction_support(session.config.dbms, "files")
        if not getattr(args, "path", None):
            raise HeadlessUsageError("read-file requires --path")
        result = read_file(session, str(args.path))
    elif action == "os_cmd":
        _require_extraction_support(session.config.dbms, "os")
        if not getattr(args, "shell_command", None):
            raise HeadlessUsageError("os-cmd requires --command")
        result = execute_command(session, str(args.shell_command))
    elif action == "hashes":
        _require_extraction_support(session.config.dbms, "hashes")
        result = extract_hashes(session)
    else:
        raise HeadlessUsageError("Choose a valid extraction command.")
    session.metadata["last_extraction"] = {
        "action": action,
        "generated_at": datetime.datetime.now(datetime.UTC).isoformat(),
    }
    _save_session_if_requested(args, session)
    return HeadlessResult(exit_code=0, rendered=json.dumps(result, indent=2, sort_keys=True))


def run_support(args: Any) -> HeadlessResult:
    matrix = build_support_matrix()
    dbms_filter = getattr(args, "dbms", None)
    if dbms_filter:
        entry = get_support_entry(dbms_filter)
        if entry is None:
            raise HeadlessUsageError(f"Unknown DBMS '{dbms_filter}'.")
        matrix = {
            "dbms_selector_values": matrix["dbms_selector_values"],
            "http_methods": matrix["http_methods"],
            "report_formats": matrix["report_formats"],
            "platform_confidence": matrix["platform_confidence"],
            "runtime_capabilities": matrix["runtime_capabilities"],
            "validation": matrix["validation"],
            "dbms": [entry],
        }
    output_format = getattr(args, "format", "table")
    if output_format == "json":
        rendered = json.dumps(matrix, indent=2, sort_keys=True)
    elif output_format == "markdown":
        rendered = render_support_matrix_markdown(matrix)
    else:
        rendered = render_support_matrix_text(matrix)
    return HeadlessResult(exit_code=0, rendered=rendered)


def run_recon(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    """Execute reconnaissance commands (tech detection or endpoint discovery)."""
    action = getattr(args, "recon_action", None)
    if not action:
        raise HeadlessUsageError("Choose a valid reconnaissance command (tech or endpoints).")

    try:
        if action == "tech":
            result = recon_tech(args)
        elif action == "endpoints":
            result = recon_endpoints(args)
        else:
            raise HeadlessUsageError(f"Unknown reconnaissance action: {action}")

        output_format = getattr(args, "format", "text")
        rendered = format_recon_output(result, output_format)
        return HeadlessResult(exit_code=0, rendered=rendered)
    except Exception as exc:
        raise HeadlessUsageError(f"Reconnaissance failed: {exc}") from exc


def _json_result(payload: Any) -> HeadlessResult:
    return HeadlessResult(
        exit_code=0,
        rendered=json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False),
    )


def _read_text_arg(path: str | None, inline: str | None = None) -> str:
    if inline not in (None, ""):
        return str(inline)
    if not path:
        raise HeadlessUsageError("Expected inline text or a file path.")
    return Path(path).read_text(encoding="utf-8")


def _request_specs_from_workflow_args(args: Any) -> list[RequestSpec]:
    if getattr(args, "raw_file", None) or getattr(args, "raw", None):
        raw = _read_text_arg(getattr(args, "raw_file", None), getattr(args, "raw", None))
        return [
            import_raw_http(
                raw,
                default_scheme=str(getattr(args, "default_scheme", "http") or "http"),
            )
        ]
    if getattr(args, "curl", None):
        return [import_curl(str(args.curl))]
    if getattr(args, "har", None):
        return import_har(Path(str(args.har)))
    raise HeadlessUsageError("Choose one request source: --raw-file, --raw, --curl, or --har.")


def _request_spec_payload(spec: RequestSpec) -> dict[str, Any]:
    return {
        "method": spec.method,
        "url": spec.url,
        "headers": dict(spec.headers),
        "cookies": dict(spec.cookies),
        "data": spec.data,
        "body_format": spec.body_format,
        "raw_body": spec.raw_body,
        "target_params": list(spec.target_params or []),
        "metadata": dict(spec.metadata),
    }


def _parse_payload_assignments(values: list[str]) -> dict[str, list[str]]:
    payloads: dict[str, list[str]] = {}
    for item in values:
        if "=" not in item:
            raise HeadlessUsageError("--payload must use marker=value syntax")
        name, value = item.split("=", 1)
        name = name.strip()
        if not name:
            raise HeadlessUsageError("--payload marker name cannot be empty")
        payloads.setdefault(name, []).append(value)
    return payloads


def run_workflow(args: Any) -> HeadlessResult:
    """Execute request workflow helper commands."""
    action = getattr(args, "workflow_action", None)
    specs = _request_specs_from_workflow_args(args)
    if action == "import":
        return _json_result({"requests": [_request_spec_payload(spec) for spec in specs]})
    if action == "hints":
        hints = passive_injection_hints(specs)
        return _json_result(
            {
                "request_count": len(specs),
                "hints": [
                    {
                        "name": hint.name,
                        "location": hint.location,
                        "value_excerpt": hint.value_excerpt,
                        "reasons": list(hint.reasons),
                        "confidence": hint.confidence,
                    }
                    for hint in hints
                ],
            }
        )
    if action == "intruder":
        if len(specs) != 1:
            raise HeadlessUsageError("workflow intruder requires exactly one request source.")
        payloads = _parse_payload_assignments(getattr(args, "payload", []) or [])
        if not payloads:
            raise HeadlessUsageError(
                "workflow intruder requires at least one --payload marker=value"
            )
        expanded = expand_payload_positions(
            specs[0],
            payloads,
            mode=str(getattr(args, "mode", "clusterbomb")),
            limit=getattr(args, "limit", None),
        )
        return _json_result(
            {
                "mode": getattr(args, "mode", "clusterbomb"),
                "count": len(expanded),
                "requests": [_request_spec_payload(spec) for spec in expanded],
            }
        )
    raise HeadlessUsageError("Choose a valid workflow command.")


def run_proxy_workspace(args: Any) -> HeadlessResult:
    """Execute local proxy workspace helper commands."""
    workspace = ProxyWorkspace(Path(str(getattr(args, "workspace", ".stealthix/proxy-workspace"))))
    action = getattr(args, "proxy_action", None)
    if action == "import":
        tags = [str(item) for item in getattr(args, "tag", []) or []]
        if getattr(args, "har", None):
            records = workspace.import_har(Path(str(args.har)))
        else:
            specs = _request_specs_from_workflow_args(args)
            records = [
                workspace.capture_request(
                    spec,
                    source=str(spec.metadata.get("origin") or "manual"),
                    tags=tags,
                    note=str(getattr(args, "note", "") or ""),
                )
                for spec in specs
            ]
        if tags and getattr(args, "har", None):
            records = [
                workspace.upsert(
                    record.with_updates(tags=tuple(dict.fromkeys([*record.tags, *tags])))
                )
                for record in records
            ]
        return _json_result(
            {
                "workspace": str(workspace.root),
                "imported": len(records),
                "records": [record.to_dict() for record in records],
            }
        )
    if action == "search":
        records = workspace.search(
            getattr(args, "query", None),
            method=getattr(args, "method", None),
            status=getattr(args, "status", None),
            tag=getattr(args, "tag", None),
            host=getattr(args, "host", None),
            limit=getattr(args, "limit", None),
        )
        return _json_result(
            {
                "workspace": str(workspace.root),
                "count": len(records),
                "records": [record.to_dict() for record in records],
            }
        )
    if action == "export":
        try:
            return HeadlessResult(
                exit_code=0,
                rendered=workspace.export_payload(format=str(getattr(args, "format", "json"))),
            )
        except ValueError as exc:
            raise HeadlessUsageError(str(exc)) from exc
    if action == "stats":
        return _json_result(workspace.stats())
    raise HeadlessUsageError("Choose a valid proxy workspace command.")


def _impact_parameters_from_args(args: Any) -> dict[str, Any]:
    params: dict[str, Any] = {}
    if getattr(args, "path", None):
        params["path"] = str(args.path)
    if getattr(args, "destination", None):
        params["path"] = str(args.destination)
    if getattr(args, "impact_command", None):
        params["command"] = str(args.impact_command)
    if getattr(args, "content", None) not in (None, ""):
        params["content"] = str(args.content)
    if getattr(args, "content_file", None):
        params["content"] = Path(str(args.content_file)).read_text(encoding="utf-8")
    return params


def _impact_operation_from_args(args: Any) -> str:
    operation = str(getattr(args, "operation", "") or "").strip().lower().replace("-", "_")
    aliases = {
        "read_file": FILE_READ,
        "file_read": FILE_READ,
        "write_file": FILE_WRITE,
        "file_write": FILE_WRITE,
        "os_cmd": OS_COMMAND,
        "command": OS_COMMAND,
        "os_command": OS_COMMAND,
        "udf": UDF_DROPPER,
        "udf_dropper": UDF_DROPPER,
    }
    if operation not in aliases:
        raise HeadlessUsageError(f"Unknown impact operation: {operation}")
    return aliases[operation]


def run_impact(args: Any, config_data: dict[str, Any]) -> HeadlessResult:
    """Execute DBMS impact capability, planning, and gated execution helpers."""
    action = getattr(args, "impact_action", None)
    if action == "matrix":
        matrix = build_capability_matrix()
        dbms = str(getattr(args, "dbms", "") or "").strip().lower()
        if dbms:
            matrix = {name: profile for name, profile in matrix.items() if name == dbms}
        return _json_result({"profiles": matrix})
    if action not in {"plan", "execute"}:
        raise HeadlessUsageError("Choose a valid impact command.")

    operation = _impact_operation_from_args(args)
    dbms = getattr(args, "dbms", None) or config_data.get("dbms")
    plan = plan_impact_operation(
        str(dbms or "auto"),
        operation,
        parameters=_impact_parameters_from_args(args),
        operator=getattr(args, "operator", None),
        target=getattr(args, "url", None),
        reason=getattr(args, "reason", None),
    )
    if action == "plan":
        return _json_result(plan.to_dict())

    session = build_session(args, config_data)
    apply_plugin(session)
    options = ImpactExecutionOptions(
        allow_file_read=bool(getattr(args, "allow_file_read", False)),
        allow_file_write=bool(getattr(args, "allow_file_write", False)),
        allow_os_command=bool(getattr(args, "allow_os_command", False)),
        allow_udf_dropper=bool(getattr(args, "allow_udf_dropper", False)),
        operator=getattr(args, "operator", None),
        reason=getattr(args, "reason", None),
    )
    result = SessionImpactExecutor(session).execute(plan, options)
    return _json_result(result.to_dict())


def run_template(args: Any) -> HeadlessResult:
    """Execute template helper commands."""
    template = load_stealthix_template(
        Path(str(args.template)),
        allow_unsafe_methods=bool(getattr(args, "allow_unsafe_methods", False)),
    )
    action = getattr(args, "template_action", None)
    if action == "requests":
        specs = request_specs_for_template(template, str(args.base_url))
        return _json_result(
            {
                "template_id": template.id,
                "requests": [_request_spec_payload(spec) for spec in specs],
            }
        )
    if action == "eval":
        body = _read_text_arg(getattr(args, "body_file", None), getattr(args, "body", ""))
        response = TemplateResponse(
            status_code=int(args.status),
            headers=_parse_headers(getattr(args, "header", []) or []),
            body=body,
        )
        result = evaluate_template(
            template,
            response,
            request_index=int(getattr(args, "request_index", 0) or 0),
        )
        return _json_result(
            {
                "template_id": result.template_id,
                "matched": result.matched,
                "matcher_results": [
                    {
                        "matcher_type": item.matcher_type,
                        "part": item.part,
                        "matched": item.matched,
                    }
                    for item in result.matcher_results
                ],
                "extracts": [
                    {
                        "name": item.name,
                        "value": item.value,
                        "extractor_type": item.extractor_type,
                    }
                    for item in result.extracts
                ],
            }
        )
    raise HeadlessUsageError("Choose a valid template command.")
