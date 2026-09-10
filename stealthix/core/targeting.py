from __future__ import annotations

from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from stealthix.core.models import TargetParam
from stealthix.core.session import ScanSession
from stealthix.detection.rest_api import (
    classify_scalar,
    discover_rest_target_params,
    method_uses_body,
)


@dataclass(frozen=True)
class InjectionPoint:
    name: str
    location: str


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self._in_form = False
        self.inputs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = (tag or "").lower()
        if t == "form":
            self._in_form = True
            return
        if not self._in_form:
            return
        if t in {"input", "textarea", "select"}:
            attrs_map = {k.lower(): (v or "") for k, v in attrs}
            name = (attrs_map.get("name") or "").strip()
            if name:
                self.inputs.append(name)

    def handle_endtag(self, tag: str) -> None:
        if (tag or "").lower() == "form":
            self._in_form = False


def discover_injection_points(session: ScanSession) -> list[InjectionPoint]:
    points: list[InjectionPoint] = []

    body_location = "query"
    if method_uses_body(session.config.method):
        body_location = "json" if session.config.body_format == "json" else "form"

    parsed = urlparse(session.config.base_url)
    query_names = set(parse_qs(parsed.query).keys())
    body_names = set(session.config.data.keys()) if isinstance(session.config.data, dict) else set()

    explicit = session.config.target_params or []
    for name in explicit:
        n = (name or "").strip()
        if n:
            if n in query_names:
                points.append(InjectionPoint(name=n, location="query"))
            elif n in body_names:
                points.append(InjectionPoint(name=n, location=body_location))
            else:
                points.append(InjectionPoint(name=n, location=body_location))

    if points:
        return _dedupe(points)

    points.extend(
        InjectionPoint(name=item.name, location=item.location)
        for item in discover_rest_target_params(session)
    )

    for name in parse_qs(parsed.query).keys():
        n = (name or "").strip()
        if n:
            points.append(InjectionPoint(name=n, location="query"))

    if method_uses_body(session.config.method):
        if isinstance(session.config.data, dict):
            for name in session.config.data.keys():
                n = (str(name) or "").strip()
                if n:
                    points.append(InjectionPoint(name=n, location=body_location))

    if session.config.level >= 3:
        try:
            from stealthix.core.http import make_request

            body, _ = make_request(session, session.config.base_url, method="GET", use_cache=True)
            parser = _FormParser()
            parser.feed(body)
            for name in parser.inputs[:200]:
                points.append(InjectionPoint(name=name, location=body_location))
        except Exception:
            pass

    return _dedupe(points)


def discover_target_params(session: ScanSession) -> list[TargetParam]:
    params: list[TargetParam] = list(discover_rest_target_params(session))

    parsed = urlparse(session.config.base_url)
    query = parse_qs(parsed.query)
    for name, values in query.items():
        n = (name or "").strip()
        if not n:
            continue
        v = values[0] if values else ""
        params.append(TargetParam(name=n, location="query", type=classify_scalar(v)))

    if method_uses_body(session.config.method):
        loc = (
            "xml"
            if (session.config.body_format or "").lower() == "xml"
            else ("json" if session.config.body_format == "json" else "form")
        )
        if isinstance(session.config.data, dict):
            for k, v in session.config.data.items():
                n = (str(k) or "").strip()
                if n:
                    params.append(TargetParam(name=n, location=loc, type=classify_scalar(v)))

    seen: set[tuple[str, str]] = set()
    out: list[TargetParam] = []
    for p in params:
        key = (p.location, p.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    if not out:
        loc = "query"
        if method_uses_body(session.config.method):
            loc = (
                "xml"
                if (session.config.body_format or "").lower() == "xml"
                else ("json" if session.config.body_format == "json" else "form")
            )
        out = [TargetParam(name="id", location=loc, type="string")]
    session.metadata["target_params"] = [p.__dict__ for p in out]
    return out


def _dedupe(points: list[InjectionPoint]) -> list[InjectionPoint]:
    seen: set[tuple[str, str]] = set()
    out: list[InjectionPoint] = []
    for p in points:
        key = (p.location, p.name)
        if key in seen:
            continue
        seen.add(key)
        out.append(p)
    return out


def _clear_runtime_overrides(session: ScanSession) -> None:
    session.runtime.pop("request_headers_override", None)


def _path_value_from_session(session: ScanSession, point: InjectionPoint) -> str | None:
    path_params = session.metadata.get("api_path_params")
    if isinstance(path_params, dict) and point.name in path_params:
        return str(path_params[point.name])
    return None


def _mutate_path(url: str, point: InjectionPoint, payload: str, session: ScanSession) -> str:
    template = str(session.metadata.get("path_template") or "").strip()
    if template and "{" + point.name + "}" in template:
        return template.replace("{" + point.name + "}", payload)
    parsed = urlparse(url)
    segments = [segment for segment in parsed.path.split("/") if segment]
    if point.name.startswith("path[") and point.name.endswith("]"):
        try:
            index = int(point.name[5:-1]) - 1
        except ValueError:
            index = -1
        if 0 <= index < len(segments):
            segments[index] = payload
            return urlunparse(parsed._replace(path="/" + "/".join(segments)))
    existing = _path_value_from_session(session, point)
    if existing:
        return urlunparse(
            parsed._replace(path=parsed.path.replace(f"/{existing}", f"/{payload}", 1))
        )
    return url


def _parse_nested_path(path: str) -> list[str | int]:
    parts: list[str | int] = []
    buffer = ""
    index_buffer = ""
    in_index = False
    for char in path:
        if char == "." and not in_index:
            if buffer:
                parts.append(buffer)
                buffer = ""
            continue
        if char == "[":
            if buffer:
                parts.append(buffer)
                buffer = ""
            in_index = True
            index_buffer = ""
            continue
        if char == "]" and in_index:
            if index_buffer.isdigit():
                parts.append(int(index_buffer))
            in_index = False
            continue
        if in_index:
            index_buffer += char
        else:
            buffer += char
    if buffer:
        parts.append(buffer)
    return parts


def _set_nested_value(data: Any, path: str, value: Any) -> Any:
    if not isinstance(data, (dict, list)):
        return {path: value}
    tokens = _parse_nested_path(path)
    if not tokens:
        return data
    current = data
    for token in tokens[:-1]:
        if isinstance(token, int):
            while isinstance(current, list) and len(current) <= token:
                current.append({})
            current = current[token]
        else:
            if not isinstance(current, dict):
                return data
            current = current.setdefault(token, {})
    last = tokens[-1]
    if isinstance(last, int):
        if not isinstance(current, list):
            return data
        while len(current) <= last:
            current.append("")
        current[last] = value
    else:
        if not isinstance(current, dict):
            return data
        current[last] = value
    return data


def apply_payload(
    session: ScanSession,
    point: InjectionPoint,
    payload: str,
) -> tuple[str, dict[str, Any] | None]:
    _clear_runtime_overrides(session)
    method = session.config.method.upper()
    if point.location == "header":
        overrides = dict(session.runtime.get("request_headers_override") or {})
        overrides[point.name] = payload
        session.runtime["request_headers_override"] = overrides
        return session.config.base_url, dict(session.config.data or {}) if isinstance(
            session.config.data, dict
        ) else session.config.data
    if point.location == "path":
        return _mutate_path(session.config.base_url, point, payload, session), dict(
            session.config.data or {}
        ) if isinstance(session.config.data, dict) else session.config.data
    if method_uses_body(method):
        data: dict[str, Any] = dict(session.config.data or {})
        if point.location in {"json", "xml"} and ("." in point.name or "[" in point.name):
            _set_nested_value(data, point.name, payload)
        else:
            data[point.name] = payload
        return session.config.base_url, data

    parsed = urlparse(session.config.base_url)
    qs = parse_qs(parsed.query)
    qs[point.name] = [payload]
    query = urlencode(qs, doseq=True, safe=":/%")
    url = urlunparse(parsed._replace(query=query))
    return url, None


def record_tested_param(session: ScanSession, *, module: str, point: InjectionPoint) -> None:
    entry = {"module": module, "name": point.name, "location": point.location}
    tested = session.metadata.setdefault("tested_params", [])
    if not isinstance(tested, list):
        tested = []
        session.metadata["tested_params"] = tested
    if entry not in tested:
        tested.append(entry)
