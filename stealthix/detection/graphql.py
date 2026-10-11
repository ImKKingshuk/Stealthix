from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import urlparse

import requests
import structlog

from stealthix.core.errors import DetectionError, NetworkError
from stealthix.core.models import Finding
from stealthix.core.session import ScanSession

logger = structlog.get_logger(__name__)


def _post_json(session: ScanSession, url: str, payload: dict[str, Any]) -> tuple[str, float]:
    headers = dict(session.config.headers)
    headers.setdefault("Content-Type", "application/json")
    proxies = (
        {"http": session.config.proxy, "https": session.config.proxy}
        if session.config.proxy
        else None
    )
    start = time.perf_counter()
    try:
        resp = requests.post(
            url,
            headers=headers,
            cookies=session.config.cookies,
            json=payload,
            proxies=proxies,
            timeout=session.config.timeout,
            verify=session.config.verify_tls,
        )
    except requests.exceptions.Timeout as e:
        raise NetworkError(f"Request timeout to {url}: {e}") from e
    except requests.exceptions.ConnectionError as e:
        raise NetworkError(f"Connection error to {url}: {e}") from e
    except requests.exceptions.RequestException as e:
        raise NetworkError(f"Request failed to {url}: {e}") from e
    elapsed = time.perf_counter() - start
    session.history.add(
        url,
        "POST",
        str(resp.status_code),
        elapsed,
        {
            "method": "POST",
            "content_type": "application/json",
            "status_code": resp.status_code,
            "headers": dict(resp.headers),
        },
    )
    return resp.text, elapsed


def detect_graphql(session: ScanSession) -> list[Finding]:
    session.metadata.setdefault("tested_params", [])
    parsed = urlparse(session.config.base_url)
    likely = "graphql" in (parsed.path or "").lower()
    if not likely:
        existing = session.config.data or {}
        likely = (
            session.config.body_format == "json"
            and isinstance(existing, dict)
            and ("query" in existing or "operationName" in existing)
        )
    if not likely:
        return []

    findings: list[Finding] = []
    q1 = {"query": "{__typename}"}
    body, elapsed = _post_json(session, session.config.base_url, q1)
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as e:
        logger.debug(f"Failed to parse GraphQL response as JSON: {e}")
        payload = None
    except DetectionError as e:
        logger.warning(f"Unexpected error parsing GraphQL response: {e}", exc_info=True)
        payload = None
    if isinstance(payload, dict) and ("data" in payload or "errors" in payload):
        findings.append(
            Finding(
                kind="graphql-endpoint",
                target=session.config.base_url,
                details={
                    "elapsed": elapsed,
                    "has_data": "data" in payload,
                    "has_errors": "errors" in payload,
                },
            )
        )
    else:
        return findings

    intro = {
        "query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}types{name}}}",
    }
    body2, elapsed2 = _post_json(session, session.config.base_url, intro)
    try:
        payload2 = json.loads(body2)
    except json.JSONDecodeError as e:
        logger.debug(f"Failed to parse GraphQL introspection response as JSON: {e}")
        payload2 = None
    except DetectionError as e:
        logger.warning(
            f"Unexpected error parsing GraphQL introspection response: {e}", exc_info=True
        )
        payload2 = None
    if (
        isinstance(payload2, dict)
        and isinstance(payload2.get("data"), dict)
        and payload2["data"].get("__schema")
    ):
        findings.append(
            Finding(
                kind="graphql-introspection",
                target=session.config.base_url,
                details={"elapsed": elapsed2, "introspection": True},
            )
        )

    bad = {"query": "{__nonexistentField}"}
    body3, elapsed3 = _post_json(session, session.config.base_url, bad)
    try:
        payload3 = json.loads(body3)
    except json.JSONDecodeError as e:
        logger.debug(f"Failed to parse GraphQL error probe response as JSON: {e}")
        payload3 = None
    except Exception as e:
        logger.warning(f"Unexpected error parsing GraphQL error probe response: {e}", exc_info=True)
        payload3 = None
    if isinstance(payload3, dict) and payload3.get("errors"):
        findings.append(
            Finding(
                kind="graphql-error-probe",
                target=session.config.base_url,
                details={"elapsed": elapsed3, "errors": payload3.get("errors")},
            )
        )

    vars_probe = {"query": "query($x:String!){__typename}", "variables": {"x": '" OR 1=1 --'}}
    body4, elapsed4 = _post_json(session, session.config.base_url, vars_probe)
    try:
        payload4 = json.loads(body4)
    except json.JSONDecodeError as e:
        logger.debug(f"Failed to parse GraphQL variables probe response as JSON: {e}")
        payload4 = None
    except Exception as e:
        logger.warning(
            f"Unexpected error parsing GraphQL variables probe response: {e}", exc_info=True
        )
        payload4 = None
    if isinstance(payload4, dict) and ("data" in payload4 or "errors" in payload4):
        findings.append(
            Finding(
                kind="graphql-variables-probe",
                target=session.config.base_url,
                details={
                    "elapsed": elapsed4,
                    "has_data": "data" in payload4,
                    "has_errors": "errors" in payload4,
                },
            )
        )
    return findings
