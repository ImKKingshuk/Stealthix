"""
Async HTTP client using Rust reqwest via PyO3.

This module provides true async HTTP I/O using the Rust reqwest client,
replacing the asyncio.to_thread wrapper with actual async operations.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any
from urllib.parse import urlencode
from xml.sax.saxutils import escape

import structlog

from stealthix.core.auth import (
    handle_auth_failure,
    has_auth,
    prepare_request_auth,
)
from stealthix.core.errors import NetworkError
from stealthix.core.metrics import get_metrics
from stealthix.core.rate_limiter import get_rate_limiter
from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body

logger = structlog.get_logger(__name__)


def _get_rust_client(proxy: str | None = None, timeout: float = 20.0, verify_tls: bool = True):
    """Create a Rust HTTP client for this request configuration."""
    from stealthix.utils import load_rust_core

    rust = load_rust_core()
    HttpClient = rust.get("HttpClient")
    if not HttpClient:
        raise RuntimeError("Rust HttpClient not available")
    return HttpClient(proxy=proxy, timeout=timeout, verify_tls=verify_tls)


def _excerpt_payload(value: Any, *, limit: int = 512) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
    else:
        text = str(value)
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def _xml_body(data: Any) -> str:
    if isinstance(data, str) and data.lstrip().startswith("<"):
        return data

    def build(name: str, value: Any) -> str:
        tag = str(name or "field")
        if isinstance(value, dict):
            return (
                f"<{tag}>"
                + "".join(build(key, child) for key, child in value.items())
                + f"</{tag}>"
            )
        if isinstance(value, list):
            return f"<{tag}>" + "".join(build("item", child) for child in value) + f"</{tag}>"
        return f"<{tag}>{escape(str(value))}</{tag}>"

    if isinstance(data, dict):
        return (
            "<request>" + "".join(build(key, value) for key, value in data.items()) + "</request>"
        )
    return f"<request><payload>{escape(str(data or ''))}</payload></request>"


def _encoded_body(data: Any, *, body_format: str) -> str:
    if body_format == "json":
        return json.dumps(data or {})
    if body_format == "xml":
        return _xml_body(data)
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    if isinstance(data, str):
        return data
    return urlencode(data or {}, doseq=True)


def _response_text(response: Any) -> str:
    if isinstance(response, str):
        return response
    if isinstance(response, bytes):
        return response.decode("utf-8", errors="replace")
    if isinstance(response, dict):
        return str(response.get("text") or response.get("body") or "")
    return str(getattr(response, "text", response))


def _response_status(response: Any) -> int | None:
    if isinstance(response, dict):
        status = response.get("status_code", response.get("status"))
    else:
        status = getattr(response, "status_code", getattr(response, "status", None))
    try:
        return int(status) if status is not None else None
    except (TypeError, ValueError):
        return None


def _response_headers(response: Any) -> dict[str, str]:
    headers = (
        response.get("headers") if isinstance(response, dict) else getattr(response, "headers", {})
    )
    return {str(key): str(value) for key, value in dict(headers or {}).items()}


def _rust_async_supports(request_method: str, body: str, request_auth: Any) -> bool:
    if request_auth is not None:
        return False
    if body and request_method != "POST":
        return False
    return True


async def _call_sync_request(
    session: ScanSession,
    url: str,
    data: Any,
    method: str | None,
    *,
    use_cache: bool,
) -> tuple[str, float]:
    from stealthix.core.http import make_request

    return await asyncio.to_thread(make_request, session, url, data, method, use_cache=use_cache)


async def make_async_request(
    session: ScanSession,
    url: str,
    data: Any = None,
    method: str | None = None,
    *,
    use_cache: bool = True,
) -> tuple[str, float]:
    """
    Make an async HTTP request using Rust reqwest client.

    Args:
        session: Scan session with configuration
        url: Target URL
        data: Request body data
        method: HTTP method (overrides session config)
        use_cache: Whether to use response caching

    Returns:
        Tuple of (response_body, elapsed_seconds)
    """
    await session.control.async_wait_if_paused()

    # Rate limiting check
    rate_limiter = get_rate_limiter()
    if not rate_limiter.acquire(url):
        wait_time = rate_limiter.wait_time(url)
        if wait_time > 0:
            logger.debug(
                "rate_limit_wait",
                url=url,
                wait_time=wait_time,
            )
            await asyncio.sleep(wait_time)

    request_method = (method or session.config.method).upper()
    if method == "POST" and session.config.method.upper() in {"PUT", "PATCH", "DELETE"}:
        request_method = session.config.method.upper()
    body_format = (session.config.body_format or "form").lower()
    request_data = data if data is not None else session.config.data
    runtime_header_overrides = {
        **dict(session.runtime.get("tamper_headers_override") or {}),
        **dict(session.runtime.get("request_headers_override") or {}),
    }
    multipart_fields = {
        str(item).strip()
        for item in (session.metadata.get("multipart_fields") or [])
        if isinstance(item, str) and str(item).strip()
    }
    if multipart_fields:
        return await _call_sync_request(session, url, data, method, use_cache=use_cache)

    request_headers, request_data, request_auth = prepare_request_auth(
        session,
        url=url,
        headers={**dict(session.config.headers or {}), **runtime_header_overrides},
        data=request_data,
        method=request_method,
        body_format=body_format,
    )
    body = (
        _encoded_body(request_data, body_format=body_format)
        if method_uses_body(request_method)
        else ""
    )
    if body and body_format == "json":
        request_headers.setdefault("Content-Type", "application/json")
    elif body and body_format == "xml":
        request_headers.setdefault("Content-Type", "application/xml")
    if not _rust_async_supports(request_method, body, request_auth):
        return await _call_sync_request(
            session, url, request_data, request_method, use_cache=use_cache
        )

    start = time.perf_counter()

    # Get Rust client and make async request
    client = _get_rust_client(
        proxy=session.config.proxy,
        timeout=session.config.timeout,
        verify_tls=session.config.verify_tls,
    )

    try:
        raw_response = await client.async_request(
            method=request_method,
            url=url,
            headers=request_headers,
            cookies=dict(session.config.cookies or {}),
            body=body,
        )
        elapsed = time.perf_counter() - start
        response_text = _response_text(raw_response)
        status_code = _response_status(raw_response)
        response_headers = _response_headers(raw_response)

        if (
            status_code in {401, 403}
            and has_auth(session)
            and handle_auth_failure(session, status_code=status_code, url=url)
        ):
            return await make_async_request(session, url, data, method, use_cache=use_cache)

        session.history.add(
            url,
            request_method,
            str(status_code) if status_code is not None else None,
            elapsed,
            {
                "method": request_method,
                "headers": response_headers,
                "content_type": response_headers.get("Content-Type", ""),
                "status_code": status_code,
                "request_headers": dict(request_headers),
                "request_body": _excerpt_payload(request_data),
                "response_excerpt": _excerpt_payload(response_text),
                "transport": "rust-async",
            },
        )
        get_metrics().increment_request(target=url, method=request_method, latency=elapsed)

        logger.debug(
            "async_request_completed",
            url=url,
            method=request_method,
            elapsed=elapsed,
            status=status_code,
        )

        return response_text, elapsed
    except Exception as e:
        elapsed = time.perf_counter() - start
        logger.error(
            "async_request_failed",
            url=url,
            method=request_method,
            error=str(e),
            elapsed=elapsed,
            exc_info=True,
        )
        raise NetworkError(f"Async HTTP request failed: {e}") from e


async def make_async_get(
    session: ScanSession,
    url: str,
    headers: dict[str, str] | None = None,
) -> tuple[str, float]:
    """
    Make an async GET request.

    Args:
        session: Scan session with configuration
        url: Target URL
        headers: Additional headers

    Returns:
        Tuple of (response_body, elapsed_seconds)
    """
    prior_override = session.runtime.get("request_headers_override")
    if headers:
        session.runtime["request_headers_override"] = {
            **dict(prior_override or {}),
            **headers,
        }
    try:
        response_text, elapsed = await make_async_request(
            session, url, method="GET", use_cache=False
        )

        logger.debug(
            "async_get_completed",
            url=url,
            elapsed=elapsed,
        )

        return response_text, elapsed
    except Exception as e:
        logger.error(
            "async_get_failed",
            url=url,
            error=str(e),
            exc_info=True,
        )
        raise NetworkError(f"Async GET request failed: {e}") from e
    finally:
        if headers:
            if prior_override is None:
                session.runtime.pop("request_headers_override", None)
            else:
                session.runtime["request_headers_override"] = prior_override


async def make_async_post(
    session: ScanSession,
    url: str,
    body: str,
    headers: dict[str, str] | None = None,
) -> tuple[str, float]:
    """
    Make an async POST request.

    Args:
        session: Scan session with configuration
        url: Target URL
        body: Request body
        headers: Additional headers

    Returns:
        Tuple of (response_body, elapsed_seconds)
    """
    prior_override = session.runtime.get("request_headers_override")
    if headers:
        session.runtime["request_headers_override"] = {
            **dict(prior_override or {}),
            **headers,
        }
    try:
        response_text, elapsed = await make_async_request(
            session,
            url,
            data=body,
            method="POST",
            use_cache=False,
        )

        logger.debug(
            "async_post_completed",
            url=url,
            elapsed=elapsed,
        )

        return response_text, elapsed
    except Exception as e:
        logger.error(
            "async_post_failed",
            url=url,
            error=str(e),
            exc_info=True,
        )
        raise NetworkError(f"Async POST request failed: {e}") from e
    finally:
        if headers:
            if prior_override is None:
                session.runtime.pop("request_headers_override", None)
            else:
                session.runtime["request_headers_override"] = prior_override


__all__ = [
    "make_async_request",
    "make_async_get",
    "make_async_post",
]
