from __future__ import annotations

from typing import Any, cast

from stealthix._tui_callback_runtime import (
    JOBS,
    config_from_tui_params,
    job_payload,
    ok_response,
    session_to_dict,
)
from stealthix.core.auth import ensure_authenticated
from stealthix.core.session import ScanSession
from stealthix.core.targeting import discover_target_params
from stealthix.crawler import Spider, SpiderOptions


def handle_scan_action(action: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if action == "auth.login":
        config = config_from_tui_params(params)
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        session = ScanSession(config=config, metadata=cast(dict[str, Any], metadata))
        ensure_authenticated(session, force=True, reason="tui.auth.login")
        return ok_response(
            f"Authenticated against {config.base_url}.",
            data={
                "auth": session.metadata.get("auth", {}),
                "headers": dict(session.config.headers),
                "cookies": dict(session.config.cookies),
                "session": session_to_dict(session),
            },
        )
    if action == "crawl.discover":
        config = config_from_tui_params(params)
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        session = ScanSession(config=config, metadata=cast(dict[str, Any], metadata))
        options = SpiderOptions(
            max_depth=max(0, int(params.get("crawl_depth", params.get("depth", 2)) or 2)),
            max_pages=max(1, int(params.get("crawl_max_pages", params.get("max_pages", 50)) or 50)),
            scope=str(params.get("crawl_scope") or params.get("scope") or "host").lower(),
            parse_robots=bool(params.get("crawl_parse_robots", params.get("parse_robots", True))),
            parse_sitemap=bool(
                params.get("crawl_parse_sitemap", params.get("parse_sitemap", True))
            ),
        )
        result = Spider(session, options=options).crawl(config.base_url)
        return ok_response(f"Discovered {result['target_count']} scan target(s).", data=result)
    if action == "scan.start":
        config = config_from_tui_params(params)
        metadata = params.get("metadata") if isinstance(params.get("metadata"), dict) else {}
        metadata = metadata if isinstance(metadata, dict) else {}
        crawl_targets = (
            params.get("crawl_targets") if isinstance(params.get("crawl_targets"), list) else None
        )
        if crawl_targets:
            metadata["crawl_targets"] = crawl_targets
        if params.get("crawl"):
            metadata["crawl_options"] = {
                "enabled": True,
                "depth": int(params.get("crawl_depth", 2) or 2),
                "max_pages": int(params.get("crawl_max_pages", 50) or 50),
                "scope": str(params.get("crawl_scope") or "host").lower(),
                "parse_robots": bool(params.get("crawl_parse_robots", True)),
                "parse_sitemap": bool(params.get("crawl_parse_sitemap", True)),
            }
        session = ScanSession(config=config, metadata=metadata)
        job = JOBS.start(session)
        return ok_response(
            f"Started scan for {config.base_url}.",
            data=job_payload(job),
            job={"job_id": job.job_id},
            logs=job.logs,
        )
    if action == "scan.poll":
        job_id = str(params.get("job_id") or "").strip()
        job = JOBS.get(job_id)
        return ok_response(job.message, data=job_payload(job), logs=job.logs)
    if action == "scan.discover_params":
        config = config_from_tui_params(params)
        metadata_param = params.get("metadata")
        session_metadata: dict[str, Any] = (
            metadata_param if isinstance(metadata_param, dict) else {}
        )
        session = ScanSession(config=config, metadata=session_metadata)
        discovered = discover_target_params(session)
        return ok_response(
            f"Discovered {len(discovered)} parameter(s).",
            data={
                "params": [
                    {"name": item.name, "location": item.location, "kind": item.kind}
                    for item in discovered
                ]
            },
        )
    if action == "scan.cancel":
        job_id = str(params.get("job_id") or "").strip()
        job = JOBS.cancel(job_id)
        return ok_response(job.message, data=job_payload(job), logs=job.logs)
    if action == "scan.pause":
        job_id = str(params.get("job_id") or "").strip()
        job = JOBS.pause(job_id)
        return ok_response(job.message, data=job_payload(job), logs=job.logs)
    if action == "scan.resume":
        job_id = str(params.get("job_id") or "").strip()
        job = JOBS.resume(job_id)
        return ok_response(job.message, data=job_payload(job), logs=job.logs)
    if action == "scan.get_result":
        job_id = str(params.get("job_id") or "").strip()
        job = JOBS.get(job_id)
        return ok_response(job.message, data=job_payload(job), logs=job.logs)
    return None
