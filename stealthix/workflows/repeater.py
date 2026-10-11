from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from stealthix.core.http import make_request
from stealthix.core.session import ScanSession
from stealthix.workflows.requests import RequestSpec


@dataclass(frozen=True)
class ReplayResult:
    spec: RequestSpec
    body: str
    elapsed: float


def replay_request(
    session: ScanSession,
    spec: RequestSpec,
    *,
    use_cache: bool = False,
) -> ReplayResult:
    original_headers = dict(session.config.headers)
    original_cookies = dict(session.config.cookies)
    original_body_format = session.config.body_format
    original_data = session.config.data
    original_multipart = list(session.metadata.get("multipart_fields") or [])
    had_multipart = "multipart_fields" in session.metadata
    try:
        session.config.headers = {**original_headers, **dict(spec.headers)}
        session.config.cookies = {**original_cookies, **dict(spec.cookies)}
        session.config.body_format = spec.body_format
        payload_data = _copy_data(spec.data) if spec.data is not None else spec.raw_body
        session.config.data = payload_data
        multipart_fields = spec.metadata.get("multipart_fields")
        if isinstance(multipart_fields, list):
            session.metadata["multipart_fields"] = list(multipart_fields)
        body, elapsed = make_request(
            session,
            spec.url,
            data=payload_data,
            method=spec.method,
            use_cache=use_cache,
        )
        return ReplayResult(spec=spec, body=body, elapsed=elapsed)
    finally:
        session.config.headers = original_headers
        session.config.cookies = original_cookies
        session.config.body_format = original_body_format
        session.config.data = original_data
        if had_multipart:
            session.metadata["multipart_fields"] = original_multipart
        else:
            session.metadata.pop("multipart_fields", None)


def _copy_data(value: Any) -> Any:
    if isinstance(value, dict):
        return dict(value)
    if isinstance(value, list):
        return list(value)
    return value


__all__ = ["ReplayResult", "replay_request"]
