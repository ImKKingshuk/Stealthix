from __future__ import annotations

import asyncio
import http.client
import json
import logging
import os
import socket
import ssl
import time
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import urlencode, urlparse
from xml.sax.saxutils import escape

import requests

from stealthix.core.auth import (
    get_requests_client,
    handle_auth_failure,
    has_auth,
    prepare_request_auth,
)
from stealthix.core.errors import NetworkError, StealthixError
from stealthix.core.metrics import get_metrics
from stealthix.core.rate_limiter import get_rate_limiter
from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.evasion.adaptive import (
    AdaptiveCandidate,
    build_retry_candidates,
    record_adaptive_result,
)
from stealthix.utils import load_rust_core
from stealthix.utils.cache import cache_enabled, get_cache, is_cacheable

logger = logging.getLogger(__name__)


def _dedupe_hints(hints: list[str]) -> list[str]:
    """Deduplicate hints while preserving order."""
    seen: set[str] = set()
    return [h for h in hints if not (h in seen or seen.add(h))]


def _session_waf_hints(session: ScanSession) -> list[str]:
    hints: list[str] = []
    wafs = session.metadata.get("waf")
    if isinstance(wafs, list):
        hints.extend(str(item).strip().lower() for item in wafs if str(item).strip())
    fingerprint = session.metadata.get("fingerprint")
    fp_hints = fingerprint.get("waf_hints") if isinstance(fingerprint, dict) else None
    if isinstance(fp_hints, list):
        hints.extend(str(item).strip().lower() for item in fp_hints if str(item).strip())
    seen: set[str] = set()
    return [item for item in hints if not (item in seen or seen.add(item))]


def _configured_retry_count(session: ScanSession) -> int:
    raw = os.environ.get("STEALTHIX_HTTP_RETRIES")
    if raw is not None:
        try:
            return max(0, int(raw))
        except ValueError:
            return 0
    return 2 if _session_waf_hints(session) or session.metadata.get("hostile_target") else 0


def _configured_backoff() -> float:
    raw = os.environ.get("STEALTHIX_HTTP_BACKOFF")
    if raw is not None:
        try:
            return max(0.0, float(raw))
        except ValueError:
            return 0.4
    return 0.4


def _retry_after_seconds(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        try:
            retry_at = parsedate_to_datetime(value)
            return max(0.0, retry_at.timestamp() - time.time())
        except (TypeError, AttributeError, OverflowError) as e:
            logger.debug(f"Failed to parse retry-after header: {e}")
            return None


def _detect_waf_hints(headers: dict[str, str], body: str) -> list[str]:
    hints: list[str] = []
    lower_headers = {str(k).lower(): str(v).lower() for k, v in headers.items()}
    server = lower_headers.get("server", "")
    body_lower = (body or "").lower()
    signatures = {
        "cloudflare": ["cloudflare", "cf-ray", "attention required"],
        "akamai": ["akamai", "akamaighost", "reference #"],
        "sucuri": ["sucuri", "x-sucuri-id", "website firewall"],
        "imperva": ["imperva", "incapsula", "request unsuccessful"],
        "modsecurity": ["modsecurity", "mod_security", "not acceptable"],
        "f5": ["big-ip", "the requested url was rejected"],
    }
    for name, tokens in signatures.items():
        if (
            any(token in server for token in tokens)
            or any(token in body_lower for token in tokens)
            or any(token in lower_headers for token in tokens)
        ):
            hints.append(name)
    seen: set[str] = set()
    return [item for item in hints if not (item in seen or seen.add(item))]


def _should_prefer_python_http(session: ScanSession) -> bool:
    if os.environ.get("STEALTHIX_FORCE_PYTHON_HTTP"):
        return True
    if session.config.tamper_auto or session.config.tamper_pipeline:
        return True
    return _configured_retry_count(session) > 0


def _record_hostile_target(
    session: ScanSession,
    *,
    status_code: int | None,
    waf_hints: list[str],
    waf_blocked: bool,
    retry_delay: float | None,
    transport: str,
) -> None:
    hostile = session.metadata.setdefault("hostile_target", {})
    if not isinstance(hostile, dict):
        return
    hostile["transport"] = transport
    hostile["last_status"] = status_code
    hostile["last_waf_hints"] = waf_hints
    hostile["blocked_responses"] = int(hostile.get("blocked_responses", 0)) + int(waf_blocked)
    hostile["retry_count"] = int(hostile.get("retry_count", 0)) + int(
        bool(retry_delay and retry_delay > 0)
    )
    hostile["rate_limited_responses"] = int(hostile.get("rate_limited_responses", 0)) + int(
        status_code == 429
    )
    if waf_hints:
        fingerprint = session.metadata.setdefault("fingerprint", {})
        if isinstance(fingerprint, dict):
            existing = fingerprint.get("waf_hints")
            existing_list = existing if isinstance(existing, list) else []
            fingerprint["waf_hints"] = list(dict.fromkeys([*existing_list, *waf_hints]))


def _get_requests_client(session: ScanSession) -> Any:
    return get_requests_client(session)


def _excerpt_payload(value: Any, *, limit: int = 512) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True)
    else:
        text = str(value)
    return text if len(text) <= limit else f"{text[: limit - 1]}…"


def _send_requests_request(
    request_method: str,
    url: str,
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    data: Any,
    body_format: str,
    multipart_fields: set[str] | None,
    auth: Any,
    proxies: dict[str, str] | None,
    timeout: float,
    verify_tls: bool,
    client: Any,
) -> requests.Response:
    request_client = client or requests
    request_callable = (
        getattr(request_client, request_method.lower(), None) or request_client.request
    )
    kwargs: dict[str, Any] = {
        "headers": headers,
        "cookies": cookies,
        "auth": auth,
        "proxies": proxies,
        "timeout": timeout,
        "verify": verify_tls,
    }
    if method_uses_body(request_method):
        if body_format == "json":
            headers.setdefault("Content-Type", "application/json")
            kwargs["json"] = data or {}
        elif body_format == "xml":
            headers.setdefault("Content-Type", "application/xml")
            kwargs["data"] = _xml_body(data)
        elif multipart_fields:
            source = data if isinstance(data, dict) else {}
            kwargs["data"] = {
                key: value for key, value in source.items() if key not in multipart_fields
            }
            kwargs["files"] = {
                key: (
                    f"{key or 'upload'}.txt",
                    str(source.get(key, "")).encode("utf-8"),
                    "application/octet-stream",
                )
                for key in multipart_fields
                if key in source
            }
        else:
            kwargs["data"] = data or {}
    if request_callable is getattr(request_client, "request", None):
        return request_callable(request_method, url, **kwargs)
    return request_callable(url, **kwargs)


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


def _raw_body_for_transport(data: Any, *, body_format: str) -> bytes:
    if body_format == "json":
        return json.dumps(data or {}).encode("utf-8")
    if body_format == "xml":
        return _xml_body(data).encode("utf-8")
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("utf-8")
    if isinstance(data, dict):
        return urlencode(data, doseq=True).encode("utf-8")
    return str(data or "").encode("utf-8")


def _send_fragmented_request(
    request_method: str,
    url: str,
    *,
    headers: dict[str, str],
    cookies: dict[str, str],
    data: Any,
    body_format: str,
    timeout: float,
    verify_tls: bool,
) -> tuple[str, int, dict[str, str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"
    body = (
        _raw_body_for_transport(data, body_format=body_format)
        if method_uses_body(request_method)
        else b""
    )
    request_headers = {**headers}
    request_headers.setdefault("Host", host)
    request_headers.setdefault("Connection", "close")
    if cookies:
        request_headers.setdefault(
            "Cookie", "; ".join(f"{key}={value}" for key, value in cookies.items())
        )
    if body and "Content-Length" not in request_headers:
        request_headers["Content-Length"] = str(len(body))
    if body and body_format == "json":
        request_headers.setdefault("Content-Type", "application/json")
    elif body and body_format == "xml":
        request_headers.setdefault("Content-Type", "application/xml")
    request_bytes = (
        f"{request_method} {path} HTTP/1.1\r\n"
        + "".join(f"{key}: {value}\r\n" for key, value in request_headers.items())
        + "\r\n"
    ).encode("utf-8")
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            if not verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=host)
        chunk_size = max(1, len(body) // 3 or len(body) or 1)
        sock.sendall(request_bytes)
        for index in range(0, len(body), chunk_size):
            sock.sendall(body[index : index + chunk_size])
        response = http.client.HTTPResponse(sock)  # type: ignore[arg-type]
        response.begin()
        text = response.read().decode("utf-8", errors="replace")
        return text, response.status, dict(response.getheaders())
    finally:
        sock.close()


def _attempt_adaptive_retry(
    session: ScanSession,
    *,
    url: str,
    request_method: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    data: Any,
    body_format: str,
    multipart_fields: set[str],
    auth: Any,
    proxies: dict[str, str] | None,
    timeout: float,
    verify_tls: bool,
    client: Any,
    use_cache: bool,
) -> tuple[str, float] | None:
    if session.runtime.get("adaptive_retry_active"):
        return None
    session.runtime["adaptive_retry_active"] = True
    try:
        for candidate in build_retry_candidates(
            session,
            url=url,
            data=data,
            headers=headers,
            method=request_method,
            body_format=body_format,
            multipart_fields=multipart_fields,
        ):
            started = time.perf_counter()
            if candidate.transport == "fragmented":
                text, status_code, response_headers = _send_fragmented_request(
                    request_method,
                    candidate.url,
                    headers=candidate.headers,
                    cookies=cookies,
                    data=candidate.data,
                    body_format=candidate.body_format,
                    timeout=timeout,
                    verify_tls=verify_tls,
                )
                response = requests.Response()
                response.status_code = status_code
                response._content = text.encode("utf-8")
                response.headers.update(response_headers)
            else:
                response = _send_requests_request(
                    request_method,
                    candidate.url,
                    headers=dict(candidate.headers),
                    cookies=cookies,
                    data=candidate.data,
                    body_format=candidate.body_format,
                    multipart_fields=multipart_fields,
                    auth=auth,
                    proxies=proxies,
                    timeout=timeout,
                    verify_tls=verify_tls,
                    client=client,
                )
                text = response.text
            elapsed = time.perf_counter() - started
            detector = (
                rust.get("WafDetector") if isinstance((rust := load_rust_core()), dict) else None
            )
            hints = _session_waf_hints(session)
            waf_blocked = False
            if detector:
                try:
                    instance = detector(hints=hints)
                    waf_blocked = bool(instance.detect(text))
                    hints = _dedupe_hints([*hints, *list(instance.last_hints())])
                except (AttributeError, TypeError, ValueError) as e:
                    logger.debug(f"WAF detector failed: {e}")
                    waf_blocked = False
                except NetworkError as e:
                    logger.warning(f"Unexpected error in WAF detector: {e}", exc_info=True)
                    waf_blocked = False
            blocked = (
                response.status_code is not None and response.status_code >= 400
            ) or waf_blocked
            record_adaptive_result(
                session, candidate, blocked=blocked, status_code=response.status_code
            )
            if not blocked:
                if use_cache and cache_enabled() and is_cacheable(candidate.url, ""):
                    get_cache().set(
                        (
                            request_method,
                            candidate.url,
                            candidate.body_format,
                            _excerpt_payload(candidate.data),
                            tuple(sorted(candidate.headers.items())),
                            tuple(sorted(cookies.items())),
                        ),
                        text,
                    )
                return text, elapsed
    finally:
        session.runtime.pop("adaptive_retry_active", None)
    return None


def make_request(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    method: str | None = None,
    *,
    use_cache: bool = True,
) -> tuple[str, float]:
    session.control.wait_if_paused()

    # Rate limiting check
    rate_limiter = get_rate_limiter()
    if not rate_limiter.acquire(url):
        wait_time = rate_limiter.wait_time(url)
        if wait_time > 0:
            logger.debug(
                f"rate_limit_wait url={url} wait_time={wait_time}",
            )
            time.sleep(wait_time)

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
    start = time.perf_counter()

    encoded = ""
    if (
        method_uses_body(request_method)
        and body_format not in {"json", "xml"}
        and not multipart_fields
    ):
        encoded = urlencode(request_data or {})

    request_headers, request_data, request_auth = prepare_request_auth(
        session,
        url=url,
        headers={**dict(session.config.headers), **runtime_header_overrides},
        data=request_data,
        method=request_method,
        body_format=body_format,
    )
    if (
        method_uses_body(request_method)
        and body_format not in {"json", "xml"}
        and not multipart_fields
    ):
        encoded = urlencode(request_data or {})

    cache_key = (
        request_method,
        url,
        body_format,
        encoded if body_format != "json" else json.dumps(request_data or {}, sort_keys=True),
        tuple(sorted(multipart_fields)),
        tuple(sorted(request_headers.items())),
        tuple(sorted(session.config.cookies.items())),
    )
    if use_cache and cache_enabled():
        cached = get_cache().get(cache_key)
        if cached is not None:
            session.history.add(
                url,
                request_method,
                "cached",
                0.0,
                {
                    "method": request_method,
                    "cached": True,
                    "request_headers": dict(request_headers),
                    "request_body": _excerpt_payload(request_data),
                    "transport": "cache",
                },
            )
            return cached, 0.0

    rust = load_rust_core()
    client_cls = rust.get("HttpClient")
    if client_cls and (
        request_method not in {"GET", "POST"}
        or (request_method == "POST" and body_format in {"json", "xml"})
        or multipart_fields
        or _should_prefer_python_http(session)
        or has_auth(session)
    ):
        client_cls = None

    if client_cls:
        client = client_cls(
            proxy=session.config.proxy,
            timeout=session.config.timeout,
            verify_tls=session.config.verify_tls,
        )
        payload = encoded if method_uses_body(request_method) else ""
        response = client.request(
            request_method, url, session.config.headers, session.config.cookies, payload
        )
        elapsed = time.perf_counter() - start
        session.history.add(
            url,
            request_method,
            None,
            elapsed,
            {
                "method": request_method,
                "transport": "rust",
                "request_headers": dict(request_headers),
                "request_body": _excerpt_payload(request_data),
                "response_excerpt": _excerpt_payload(response),
            },
        )
        if use_cache and cache_enabled() and is_cacheable(url, payload):
            get_cache().set(cache_key, response)
        # Track metrics
        metrics = get_metrics()
        metrics.increment_request(target=url, method=request_method, latency=elapsed)
        return response, elapsed

    headers = dict(request_headers)
    proxies = (
        {"http": session.config.proxy, "https": session.config.proxy}
        if session.config.proxy
        else None
    )
    request_client = _get_requests_client(session)
    max_retries = _configured_retry_count(session)
    base_backoff = _configured_backoff()
    response: requests.Response | None = None
    attempts: list[dict[str, Any]] = []
    last_error: Exception | None = None
    reauth_attempted = False
    retry_budget = max_retries

    for attempt in range(max_retries + 1 + int(has_auth(session))):
        attempt_start = time.perf_counter()
        try:
            response = _send_requests_request(
                request_method,
                url,
                headers=headers,
                cookies=session.config.cookies,
                data=request_data,
                body_format=body_format,
                multipart_fields=multipart_fields,
                auth=request_auth,
                proxies=proxies,
                timeout=session.config.timeout,
                verify_tls=session.config.verify_tls,
                client=request_client,
            )
        except requests.RequestException as exc:
            elapsed = time.perf_counter() - attempt_start
            attempts.append({"attempt": attempt + 1, "elapsed": elapsed, "error": str(exc)})
            last_error = exc
            if retry_budget <= 0:
                raise
            retry_budget -= 1
            delay = base_backoff * (attempt + 1)
            _record_hostile_target(
                session,
                status_code=None,
                waf_hints=[],
                waf_blocked=False,
                retry_delay=delay,
                transport="python",
            )
            if delay > 0:
                time.sleep(delay)
            continue

        elapsed = time.perf_counter() - attempt_start
        if hasattr(request_client, "cookies"):
            cookie_updates = {
                str(key): str(value)
                for key, value in requests.utils.dict_from_cookiejar(request_client.cookies).items()
            }
            session.config.cookies.update(cookie_updates)
        text = response.text
        response_headers = dict(response.headers)
        if (
            response.status_code in {401, 403}
            and not reauth_attempted
            and handle_auth_failure(session, status_code=response.status_code, url=url)
        ):
            reauth_attempted = True
            headers, request_data, request_auth = prepare_request_auth(
                session,
                url=url,
                headers={**dict(session.config.headers), **runtime_header_overrides},
                data=data if data is not None else session.config.data,
                method=request_method,
                body_format=body_format,
            )
            continue
        waf_hints = _detect_waf_hints(response_headers, text)
        retry_after = _retry_after_seconds(response.headers.get("Retry-After"))
        waf_blocked = response.status_code in {403, 406, 409} or bool(waf_hints)
        transient = response.status_code in {429, 500, 502, 503, 504}
        attempts.append(
            {
                "attempt": attempt + 1,
                "status_code": response.status_code,
                "elapsed": elapsed,
                "retry_after": retry_after,
                "waf_hints": waf_hints,
                "waf_blocked": waf_blocked,
            }
        )
        should_retry = retry_budget > 0 and (waf_blocked or transient)
        delay = (
            retry_after
            if retry_after is not None
            else (base_backoff * (attempt + 1) if should_retry else None)
        )
        _record_hostile_target(
            session,
            status_code=response.status_code,
            waf_hints=waf_hints,
            waf_blocked=waf_blocked,
            retry_delay=delay if should_retry else None,
            transport="python",
        )
        if not should_retry:
            break
        retry_budget -= 1
        headers.setdefault("Cache-Control", "no-cache")
        if delay and delay > 0:
            time.sleep(delay)

    if response is None:
        if last_error is not None:
            raise last_error
        raise RuntimeError("HTTP request did not produce a response")

    elapsed = time.perf_counter() - start
    final_waf_hints = _detect_waf_hints(dict(response.headers), response.text)
    waf_blocked = response.status_code in {403, 406, 409} or bool(final_waf_hints)
    session.history.add(
        url,
        request_method,
        str(response.status_code),
        elapsed,
        {
            "method": request_method,
            "headers": dict(response.headers),
            "content_type": response.headers.get("Content-Type", ""),
            "status_code": response.status_code,
            "request_headers": dict(headers),
            "request_body": _excerpt_payload(request_data),
            "response_excerpt": _excerpt_payload(response.text),
            "attempts": attempts,
            "retried": len(attempts) > 1,
            "waf_hints": final_waf_hints,
            "waf_blocked": waf_blocked,
            "transport": "python",
        },
    )
    text = response.text
    if use_cache and cache_enabled():
        payload = (
            encoded
            if method_uses_body(request_method)
            and body_format not in {"json", "xml"}
            and not multipart_fields
            else ""
        )
        blocked = (response.status_code is not None and response.status_code >= 400) or waf_blocked
        if is_cacheable(url, payload) and not blocked:
            get_cache().set(cache_key, text)
    # Track metrics
    metrics = get_metrics()
    metrics.increment_request(target=url, method=request_method, latency=elapsed)
    if (
        (response.status_code is not None and response.status_code >= 400) or waf_blocked
    ) and session.config.tamper_retry_budget > 0:
        retried = _attempt_adaptive_retry(
            session,
            url=url,
            request_method=request_method,
            headers=request_headers,
            cookies=session.config.cookies,
            data=request_data,
            body_format=body_format,
            multipart_fields=multipart_fields,
            auth=request_auth,
            proxies={"http": session.config.proxy, "https": session.config.proxy}
            if session.config.proxy
            else None,
            timeout=session.config.timeout,
            verify_tls=session.config.verify_tls,
            client=_get_requests_client(session),
            use_cache=use_cache,
        )
        if retried is not None:
            session.runtime.pop("request_headers_override", None)
            session.runtime.pop("tamper_headers_override", None)
            return retried
    session.runtime.pop("request_headers_override", None)
    session.runtime.pop("tamper_headers_override", None)
    return text, elapsed


async def async_make_request(
    session: ScanSession,
    url: str,
    data: dict[str, Any] | None = None,
    method: str | None = None,
    *,
    use_cache: bool = True,
) -> tuple[str, float]:
    return await asyncio.to_thread(make_request, session, url, data, method, use_cache=use_cache)
