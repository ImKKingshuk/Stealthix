from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from stealthix.core.models import Finding
from stealthix.core.session import ScanSession
from stealthix.core.targeting import (
    InjectionPoint,
    apply_payload,
    discover_injection_points,
    record_tested_param,
)
from stealthix.detection.rest_api import method_uses_body
from stealthix.plugins.base import Plugin
from stealthix.plugins.selector import select_plugin
from stealthix.utils import load_rust_core


def _safe_error(error: Exception) -> str:
    message = str(error).strip()
    if len(message) > 300:
        message = f"{message[:297]}..."
    return f"{error.__class__.__name__}: {message}" if message else error.__class__.__name__


def _record_plugin_error(
    session: ScanSession, *, phase: str, plugin: str, error: Exception
) -> None:
    errors = session.metadata.setdefault("plugin_errors", [])
    if isinstance(errors, list):
        errors.append({"phase": phase, "plugin": plugin, "error": _safe_error(error)})


def plugin_to_dict(plugin: Plugin) -> dict[str, Any]:
    return {
        "name": plugin.name,
        "family": plugin.family,
        "payloads": list(plugin.payloads),
        "fingerprints": list(plugin.fingerprints),
        "error_signatures": list(plugin.error_signatures),
        "version_queries": list(plugin.version_queries),
        "privilege_checks": list(plugin.privilege_checks),
        "os_queries": list(getattr(plugin, "os_queries", [])),
        "preferred_techniques": plugin.preferred_techniques,
        "extraction_profiles": dict(plugin.extraction_profiles),
    }


def _double_url_encode(payload: str) -> str:
    return quote(quote(payload, safe=""), safe="")


def apply_plugin(session: ScanSession) -> dict[str, Any] | None:
    plugin: Plugin | None = None
    response_text: str | None = None
    if session.config.dbms:
        plugin = select_plugin(session.config.dbms)
    elif session.config.level >= 2:
        from stealthix.detection.common import _make_request

        try:
            if method_uses_body(session.config.method):
                response_text, _ = _make_request(
                    session,
                    session.config.base_url,
                    session.config.data or {},
                    "POST",
                )
            else:
                response_text, _ = _make_request(session, session.config.base_url)
        except Exception:
            response_text = None
        if session.history.entries:
            last = session.history.entries[-1]
            meta = last.get("metadata") if isinstance(last, dict) else None
            headers = meta.get("headers") if isinstance(meta, dict) else None
            if isinstance(headers, dict):
                server = str(headers.get("Server") or headers.get("server") or "")
                powered = str(headers.get("X-Powered-By") or headers.get("x-powered-by") or "")
                waf_hints: list[str] = []
                lower_keys = {str(k).lower(): str(v) for k, v in headers.items()}
                if (
                    "cf-ray" in lower_keys
                    or "cf-cache-status" in lower_keys
                    or "cloudflare" in server.lower()
                ):
                    waf_hints.append("cloudflare")
                if "x-sucuri-id" in lower_keys or "sucuri" in server.lower():
                    waf_hints.append("sucuri")
                if "x-akamai-transformed" in lower_keys or "akamai" in server.lower():
                    waf_hints.append("akamai")
                os_hint = "unknown"
                if "asp.net" in powered.lower() or "win" in server.lower():
                    os_hint = "windows"
                if (
                    "ubuntu" in server.lower()
                    or "debian" in server.lower()
                    or "linux" in server.lower()
                ):
                    os_hint = "linux"
                session.metadata.setdefault("fingerprint", {})
                fp = session.metadata["fingerprint"]
                if isinstance(fp, dict):
                    fp.setdefault("server", server)
                    fp.setdefault("powered_by", powered)
                    fp.setdefault("os", os_hint)
                    if waf_hints:
                        fp.setdefault("waf_hints", waf_hints)
        plugin = select_plugin(None, response_text)
    if not plugin:
        return None

    plugin_dict = plugin_to_dict(plugin)
    session.metadata["plugin"] = plugin_dict
    try:
        runtime_result = plugin.apply(session)
        if isinstance(runtime_result, dict):
            plugin_runtime = session.runtime.setdefault("plugins", {})
            if isinstance(plugin_runtime, dict):
                plugin_runtime[plugin.name] = runtime_result
    except Exception as e:
        _record_plugin_error(session, phase="apply", plugin=plugin.name, error=e)
    if response_text:
        lower = response_text.lower()
        waf_body_hints: list[str] = []
        body_signatures = {
            "cloudflare": ["cloudflare", "cf-ray", "attention required"],
            "akamai": ["akamai", "akamaighost", "reference #"],
            "sucuri": ["sucuri website firewall", "access denied - sucuri"],
            "imperva": ["incapsula", "imperva", "request unsuccessful"],
            "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
            "f5": ["the requested url was rejected", "big-ip"],
        }
        for name, sigs in body_signatures.items():
            if any(sig in lower for sig in sigs):
                waf_body_hints.append(name)
        if waf_body_hints:
            session.metadata.setdefault("fingerprint", {})
            fp = session.metadata.get("fingerprint")
            if isinstance(fp, dict):
                existing = fp.get("waf_hints")
                if not isinstance(existing, list):
                    existing = []
                merged = list(dict.fromkeys([*existing, *waf_body_hints]))
                fp["waf_hints"] = merged
        rust = load_rust_core()
        waf_cls = rust.get("WafDetector")
        if waf_cls:
            try:
                waf = waf_cls()
                session.metadata["waf"] = waf.detect(response_text, [])
            except Exception:
                pass
    if not session.config.dbms:
        session.config.dbms = plugin_dict["name"]
    if not session.config.technique and plugin_dict.get("preferred_techniques"):
        raw = str(plugin_dict["preferred_techniques"])
        allowed = set()
        if session.config.level >= 1:
            allowed.update({"B", "E"})
        if session.config.level >= 2:
            allowed.add("U")
        if session.config.level >= 3:
            allowed.add("T")
        if session.config.level >= 4 and session.config.risk >= 2:
            allowed.add("S")
        filtered = "".join([ch for ch in raw.upper() if ch in allowed])
        session.config.technique = filtered or raw
        session.metadata["technique_source"] = "plugin"
    return plugin_dict


def run_plugin_checks(session: ScanSession, plugin_dict: dict[str, Any]) -> list[Finding]:
    from stealthix.detection.common import _make_request

    findings: list[Finding] = []
    points = discover_injection_points(session)
    if not points:
        loc = (
            "query"
            if not method_uses_body(session.config.method)
            else ("json" if session.config.body_format == "json" else "form")
        )
        points = [InjectionPoint(name="id", location=loc)]

    def update_fp(payload: str, snippet: str) -> None:
        fp = session.metadata.setdefault("fingerprint", {})
        if not isinstance(fp, dict):
            return
        plugin_name = str(plugin_dict.get("name") or "")
        text = snippet
        lower = text.lower()

        if plugin_name in {"mysql", "mariadb"}:
            m = re.search(r"\\b(\\d+\\.\\d+\\.\\d+(?:[-+][\\w.]+)?)\\b", text)
            if m and "version" in payload.lower():
                fp.setdefault("dbms_version", m.group(1))
            if "user()" in payload.lower() or "current_user" in payload.lower():
                u = re.search(r"([\\w.-]+@[^\\s<>{}\\\"]{1,60})", text)
                if u:
                    fp.setdefault("current_user", u.group(1))
                    fp.setdefault("is_admin", u.group(1).lower().startswith("root@"))
            if "database" in payload.lower():
                d = re.search(r"\\b([a-zA-Z0-9_]{1,64})\\b", text)
                if d:
                    fp.setdefault("database", d.group(1))
            if "version_compile_os" in payload.lower():
                if "win" in lower:
                    fp.setdefault("os", "windows")
                elif "linux" in lower or "unix" in lower or "debian" in lower or "ubuntu" in lower:
                    fp.setdefault("os", "linux")

        if plugin_name == "postgresql":
            m = re.search(r"postgresql\\s+([0-9.]+)", lower)
            if m:
                fp.setdefault("dbms_version", m.group(1))
            if "current_user" in payload.lower() or "session_user" in payload.lower():
                u = re.search(r"\\b([a-zA-Z0-9_]{1,64})\\b", text)
                if u:
                    fp.setdefault("current_user", u.group(1))
            if "version()" in payload.lower():
                if "windows" in lower:
                    fp.setdefault("os", "windows")
                elif "linux" in lower:
                    fp.setdefault("os", "linux")

        if plugin_name == "mssql":
            if "@@version" in payload.lower():
                if "microsoft sql server" in lower:
                    fp.setdefault("dbms_version", "mssql")
                if "windows" in lower:
                    fp.setdefault("os", "windows")
            if "system_user" in payload.lower():
                u = re.search(r"\\b([a-zA-Z0-9_\\\\.-]{1,80})\\b", text)
                if u:
                    fp.setdefault("current_user", u.group(1))
            if "is_srvrolemember" in payload.lower():
                fp.setdefault("is_admin", "1" in lower or "true" in lower)

        if plugin_name == "oracle":
            if "banner" in payload.lower():
                if "windows" in lower:
                    fp.setdefault("os", "windows")
                elif "linux" in lower:
                    fp.setdefault("os", "linux")
            if "user from dual" in payload.lower() and text.strip():
                fp.setdefault("current_user", text.strip().split()[0][:64])

        if plugin_name == "sqlite":
            m = re.search(r"\\b([0-9]+\\.[0-9]+\\.[0-9]+)\\b", text)
            if m:
                fp.setdefault("dbms_version", m.group(1))

    if session.config.level >= 2:
        for point in points:
            record_tested_param(session, module="plugin-version", point=point)
            for payload in plugin_dict.get("version_queries", []):
                encoded = _double_url_encode(payload)
                try:
                    if method_uses_body(session.config.method):
                        target, data = apply_payload(session, point, payload)
                        body, elapsed = _make_request(session, target, data, "POST")
                    else:
                        target, _ = apply_payload(session, point, encoded)
                        body, elapsed = _make_request(session, target)
                except Exception as e:
                    _record_plugin_error(
                        session,
                        phase="version",
                        plugin=str(plugin_dict.get("name") or ""),
                        error=e,
                    )
                    continue
                findings.append(
                    Finding(
                        kind="dbms-version",
                        target=target,
                        details={
                            "parameter": point.name,
                            "location": point.location,
                            "payload": payload,
                            "elapsed": elapsed,
                            "snippet": body[:2000],
                        },
                        parameter=point.name,
                        location=point.location,
                    )
                )
                update_fp(payload, body[:5000])

    if session.config.level >= 3:
        for point in points:
            record_tested_param(session, module="plugin-privilege", point=point)
            for payload in plugin_dict.get("privilege_checks", []):
                encoded = _double_url_encode(payload)
                try:
                    if method_uses_body(session.config.method):
                        target, data = apply_payload(session, point, payload)
                        body, elapsed = _make_request(session, target, data, "POST")
                    else:
                        target, _ = apply_payload(session, point, encoded)
                        body, elapsed = _make_request(session, target)
                except Exception as e:
                    _record_plugin_error(
                        session,
                        phase="privilege",
                        plugin=str(plugin_dict.get("name") or ""),
                        error=e,
                    )
                    continue
                findings.append(
                    Finding(
                        kind="dbms-privilege",
                        target=target,
                        details={
                            "parameter": point.name,
                            "location": point.location,
                            "payload": payload,
                            "elapsed": elapsed,
                            "snippet": body[:2000],
                        },
                        parameter=point.name,
                        location=point.location,
                    )
                )
                update_fp(payload, body[:5000])

    if session.config.level >= 3:
        for point in points:
            record_tested_param(session, module="plugin-os", point=point)
            for payload in plugin_dict.get("os_queries", []):
                encoded = _double_url_encode(payload)
                try:
                    if method_uses_body(session.config.method):
                        target, data = apply_payload(session, point, payload)
                        body, elapsed = _make_request(session, target, data, "POST")
                    else:
                        target, _ = apply_payload(session, point, encoded)
                        body, elapsed = _make_request(session, target)
                except Exception as e:
                    _record_plugin_error(
                        session,
                        phase="os",
                        plugin=str(plugin_dict.get("name") or ""),
                        error=e,
                    )
                    continue
                findings.append(
                    Finding(
                        kind="dbms-os",
                        target=target,
                        details={
                            "parameter": point.name,
                            "location": point.location,
                            "payload": payload,
                            "elapsed": elapsed,
                            "snippet": body[:2000],
                        },
                        parameter=point.name,
                        location=point.location,
                    )
                )
                update_fp(payload, body[:5000])

    return findings
