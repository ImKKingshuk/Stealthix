from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, cast

from stealthix.core.session import ScanSession
from stealthix.evasion.adaptive import infer_waf_vendor, resolve_tamper_pipeline, tamper_payload
from stealthix.utils.rust import load_rust_core

_SPECIFIC_BYPASS_CLASSES = {
    "cloudflare": "CloudflareBypass",
    "modsecurity": "ModSecurityBypass",
}


def _dedupe_modes(modes: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for mode in modes:
        item = str(mode or "").strip().lower()
        if not item or item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _candidate_modes(session: ScanSession) -> list[str]:
    explicit = (os.environ.get("STEALTHIX_WAF_BYPASS") or "").strip().lower()
    wafs = session.metadata.get("waf") or []
    fingerprint = session.metadata.get("fingerprint")
    fp_hints = fingerprint.get("waf_hints") if isinstance(fingerprint, dict) else []

    modes: list[str] = []
    if explicit and explicit != "none":
        modes.append(explicit)
    if isinstance(wafs, list):
        modes.extend(str(item) for item in wafs)
    if isinstance(fp_hints, list):
        modes.extend(str(item) for item in fp_hints)

    deduped = _dedupe_modes(modes)
    if deduped:
        deduped.append("generic")
    return _dedupe_modes(deduped)


def _resolve_bypass_class(rust: dict[str, object], mode: str) -> object | None:
    class_name = _SPECIFIC_BYPASS_CLASSES.get(mode)
    if class_name:
        return rust.get(class_name)
    if mode == "generic" or mode:
        return rust.get("PayloadObfuscator")
    return None


def apply_waf_bypass(session: ScanSession, payload: str) -> str:
    rust = load_rust_core()
    transformed = payload
    applied_modes: list[str] = []

    for mode in _candidate_modes(session):
        bypass_cls = _resolve_bypass_class(rust, mode)
        if not bypass_cls:
            continue
        try:
            bypass_callable = cast(Callable[..., Any], bypass_cls)
            bypass = bypass_callable()
            candidate = bypass.apply(transformed)
        except Exception:
            continue
        if isinstance(candidate, str) and candidate:
            transformed = candidate
            applied_modes.append(mode)

    applied_scripts: list[str] = []
    header_overrides: dict[str, str] = {}
    if session.config.tamper_pipeline:
        tampered, header_overrides, applied_scripts = tamper_payload(
            session,
            transformed,
            body_format=session.config.body_format,
        )
        if header_overrides:
            existing = dict(session.runtime.get("tamper_headers_override") or {})
            existing.update(header_overrides)
            session.runtime["tamper_headers_override"] = existing
        transformed = tampered

    if applied_modes or applied_scripts:
        session.metadata["bypass"] = {
            "modes": applied_modes,
            "vendor": infer_waf_vendor(session),
            "pipeline": applied_scripts
            or resolve_tamper_pipeline(session, body_format=session.config.body_format),
            "headers": header_overrides,
            "applied": transformed != payload,
        }
    return transformed
