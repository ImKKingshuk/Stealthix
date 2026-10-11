from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from os import PathLike
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml
from jsonschema import Draft202012Validator

from stealthix.workflows.requests import RequestSpec, normalize_request_spec

SAFE_HTTP_METHODS = {"GET", "HEAD"}
SUPPORTED_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
UNSAFE_TEMPLATE_KEYS = {"attack", "payloads", "raw", "unsafe"}


class TemplateValidationError(ValueError):
    pass


@dataclass(frozen=True)
class TemplateMatcher:
    type: str
    part: str = "body"
    words: list[str] = field(default_factory=list)
    regex: list[str] = field(default_factory=list)
    status: list[int] = field(default_factory=list)
    condition: str = "or"
    case_insensitive: bool = False


@dataclass(frozen=True)
class TemplateExtractor:
    type: str
    part: str = "body"
    regex: list[str] = field(default_factory=list)
    name: str | None = None
    group: int = 0


@dataclass(frozen=True)
class TemplateHttpRequest:
    method: str
    path: list[str]
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    matchers_condition: str = "or"
    matchers: list[TemplateMatcher] = field(default_factory=list)
    extractors: list[TemplateExtractor] = field(default_factory=list)


@dataclass(frozen=True)
class StealthixTemplate:
    id: str
    info: dict[str, Any]
    http: list[TemplateHttpRequest]
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TemplateResponse:
    status_code: int
    body: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    url: str | None = None


@dataclass(frozen=True)
class MatchResult:
    matcher_type: str
    part: str
    matched: bool


@dataclass(frozen=True)
class ExtractedValue:
    name: str
    value: str
    extractor_type: str


@dataclass(frozen=True)
class TemplateEvaluation:
    template_id: str
    matched: bool
    matcher_results: list[MatchResult]
    extracts: list[ExtractedValue]


TEMPLATE_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["id", "http"],
    "additionalProperties": True,
    "properties": {
        "id": {"type": "string", "minLength": 1},
        "info": {"type": "object"},
        "http": {
            "type": "array",
            "minItems": 1,
            "items": {
                "type": "object",
                "required": ["method", "path", "matchers"],
                "additionalProperties": True,
                "properties": {
                    "method": {"type": "string"},
                    "path": {
                        "oneOf": [
                            {"type": "string", "minLength": 1},
                            {
                                "type": "array",
                                "minItems": 1,
                                "items": {"type": "string", "minLength": 1},
                            },
                        ]
                    },
                    "headers": {"type": "object"},
                    "body": {"type": "string"},
                    "matchers-condition": {"enum": ["and", "or", "AND", "OR"]},
                    "matchers": {
                        "type": "array",
                        "minItems": 1,
                        "items": {
                            "type": "object",
                            "required": ["type"],
                            "additionalProperties": True,
                            "properties": {
                                "type": {"enum": ["word", "regex", "status"]},
                                "part": {"type": "string"},
                                "words": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "regex": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "status": {
                                    "type": "array",
                                    "items": {"type": "integer"},
                                },
                                "condition": {"enum": ["and", "or", "AND", "OR"]},
                                "case-insensitive": {"type": "boolean"},
                            },
                        },
                    },
                    "extractors": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["type"],
                            "additionalProperties": True,
                            "properties": {
                                "type": {"enum": ["regex"]},
                                "part": {"type": "string"},
                                "regex": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                                "name": {"type": "string"},
                                "group": {"type": "integer", "minimum": 0},
                            },
                        },
                    },
                },
            },
        },
    },
}


def load_stealthix_template(
    source: str | Path | dict[str, Any],
    *,
    allow_unsafe_methods: bool = False,
) -> StealthixTemplate:
    document = _load_document(source)
    errors = sorted(Draft202012Validator(TEMPLATE_SCHEMA).iter_errors(document), key=str)
    if errors:
        raise TemplateValidationError("; ".join(str(error) for error in errors))
    _validate_safe_template(document, allow_unsafe_methods=allow_unsafe_methods)
    return _build_template(document)


def request_specs_for_template(template: StealthixTemplate, base_url: str) -> list[RequestSpec]:
    specs: list[RequestSpec] = []
    for request in template.http:
        for path in request.path:
            url = _render_path(path, base_url)
            body = _render_variables(request.body, base_url)
            headers = {
                str(key): _render_variables(str(value), base_url)
                for key, value in request.headers.items()
            }
            specs.append(
                normalize_request_spec(
                    method=request.method,
                    url=url,
                    headers=headers,
                    body=body,
                    metadata={"origin": "stealthix-template", "template_id": template.id},
                )
            )
    return specs


def evaluate_template(
    template: StealthixTemplate,
    response: TemplateResponse | dict[str, Any],
    *,
    request_index: int = 0,
) -> TemplateEvaluation:
    normalized_response = _coerce_response(response)
    if request_index >= len(template.http):
        raise IndexError("request_index is outside template HTTP request list")
    request = template.http[request_index]
    matcher_results = [
        _evaluate_matcher(matcher, normalized_response) for matcher in request.matchers
    ]
    matched = _combine([item.matched for item in matcher_results], request.matchers_condition)
    extracts = _run_extractors(request.extractors, normalized_response) if matched else []
    return TemplateEvaluation(
        template_id=template.id,
        matched=matched,
        matcher_results=matcher_results,
        extracts=extracts,
    )


def _load_document(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    text = _source_text(source)
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        parsed = yaml.safe_load(text)
    if not isinstance(parsed, dict):
        raise TemplateValidationError("template must decode to an object")
    return parsed


def _source_text(source: str | PathLike[str]) -> str:
    if isinstance(source, PathLike):
        return Path(source).read_text(encoding="utf-8")
    text = str(source)
    if "\n" in text or text.lstrip().startswith(("{", "[")):
        return text
    path = Path(text)
    try:
        if path.exists():
            return path.read_text(encoding="utf-8")
    except OSError:
        return text
    return text


def _validate_safe_template(document: dict[str, Any], *, allow_unsafe_methods: bool) -> None:
    for key in ("code", "javascript", "network", "tcp", "dns", "ssl", "headless"):
        if key in document:
            raise TemplateValidationError(f"unsupported active protocol block: {key}")
    for request in document.get("http", []):
        if not isinstance(request, dict):
            continue
        forbidden = sorted(UNSAFE_TEMPLATE_KEYS.intersection(request.keys()))
        if forbidden:
            raise TemplateValidationError(f"unsupported active HTTP fields: {', '.join(forbidden)}")
        method = str(request.get("method") or "GET").upper()
        if method not in SUPPORTED_HTTP_METHODS:
            raise TemplateValidationError(f"unsupported HTTP method: {method}")
        if not allow_unsafe_methods and method not in SAFE_HTTP_METHODS:
            raise TemplateValidationError(
                f"unsafe method {method} requires allow_unsafe_methods=True"
            )


def _build_template(document: dict[str, Any]) -> StealthixTemplate:
    requests = []
    for item in document.get("http", []):
        request = item if isinstance(item, dict) else {}
        raw_path = request.get("path")
        paths = [raw_path] if isinstance(raw_path, str) else list(raw_path or [])
        requests.append(
            TemplateHttpRequest(
                method=str(request.get("method") or "GET").upper(),
                path=[str(path) for path in paths],
                headers={str(k): str(v) for k, v in dict(request.get("headers") or {}).items()},
                body=str(request["body"]) if "body" in request else None,
                matchers_condition=str(request.get("matchers-condition") or "or").lower(),
                matchers=[_build_matcher(entry) for entry in request.get("matchers", [])],
                extractors=[_build_extractor(entry) for entry in request.get("extractors", [])],
            )
        )
    return StealthixTemplate(
        id=str(document["id"]),
        info=dict(document.get("info") or {}),
        http=requests,
        metadata={"source": "stealthix-template"},
    )


def _build_matcher(entry: dict[str, Any]) -> TemplateMatcher:
    return TemplateMatcher(
        type=str(entry.get("type") or "").lower(),
        part=str(entry.get("part") or "body").lower(),
        words=[str(item) for item in entry.get("words", [])],
        regex=[str(item) for item in entry.get("regex", [])],
        status=[int(item) for item in entry.get("status", [])],
        condition=str(entry.get("condition") or "or").lower(),
        case_insensitive=bool(entry.get("case-insensitive", False)),
    )


def _build_extractor(entry: dict[str, Any]) -> TemplateExtractor:
    return TemplateExtractor(
        type=str(entry.get("type") or "").lower(),
        part=str(entry.get("part") or "body").lower(),
        regex=[str(item) for item in entry.get("regex", [])],
        name=str(entry.get("name")) if entry.get("name") else None,
        group=int(entry.get("group") or 0),
    )


def _evaluate_matcher(matcher: TemplateMatcher, response: TemplateResponse) -> MatchResult:
    part = _response_part(response, matcher.part)
    if matcher.type == "status":
        matched = response.status_code in matcher.status
    elif matcher.type == "word":
        haystack = part.lower() if matcher.case_insensitive else part
        checks = [
            (word.lower() if matcher.case_insensitive else word) in haystack
            for word in matcher.words
        ]
        matched = _combine(checks, matcher.condition)
    elif matcher.type == "regex":
        flags = re.IGNORECASE if matcher.case_insensitive else 0
        checks: list[bool] = []
        for pattern in matcher.regex:
            try:
                checks.append(bool(re.search(pattern, part, flags=flags)))
            except re.error:
                checks.append(False)
        matched = _combine(checks, matcher.condition)
    else:
        matched = False
    return MatchResult(matcher_type=matcher.type, part=matcher.part, matched=matched)


def _run_extractors(
    extractors: list[TemplateExtractor], response: TemplateResponse
) -> list[ExtractedValue]:
    values: list[ExtractedValue] = []
    for extractor in extractors:
        if extractor.type != "regex":
            continue
        part = _response_part(response, extractor.part)
        for pattern in extractor.regex:
            try:
                iterator = list(re.finditer(pattern, part))
            except re.error:
                continue
            for match in iterator:
                group = extractor.group if extractor.group <= (match.lastindex or 0) else 0
                name = extractor.name or f"{extractor.part}.regex"
                values.append(
                    ExtractedValue(name=name, value=match.group(group), extractor_type="regex")
                )
    return values


def _combine(values: list[bool], condition: str) -> bool:
    if not values:
        return False
    return all(values) if str(condition).lower() == "and" else any(values)


def _coerce_response(response: TemplateResponse | dict[str, Any]) -> TemplateResponse:
    if isinstance(response, TemplateResponse):
        return response
    return TemplateResponse(
        status_code=int(response.get("status_code") or response.get("status") or 0),
        body=str(response.get("body") or response.get("text") or ""),
        headers={str(k): str(v) for k, v in dict(response.get("headers") or {}).items()},
        url=str(response.get("url")) if response.get("url") else None,
    )


def _response_part(response: TemplateResponse, part: str) -> str:
    normalized = str(part or "body").lower()
    if normalized == "body":
        return response.body
    if normalized in {"header", "headers", "all_headers"}:
        return "\n".join(f"{key}: {value}" for key, value in response.headers.items())
    if normalized == "status_code":
        return str(response.status_code)
    if normalized == "raw":
        return (
            f"HTTP {response.status_code}\n"
            + "\n".join(f"{key}: {value}" for key, value in response.headers.items())
            + "\n\n"
            + response.body
        )
    return response.body


def _render_path(path: str, base_url: str) -> str:
    rendered = _render_variables(path, base_url)
    if rendered.startswith(("http://", "https://")):
        return rendered
    return urljoin(base_url.rstrip("/") + "/", rendered.lstrip("/"))


def _render_variables(value: str | None, base_url: str) -> str:
    if value is None:
        return ""
    parsed = urlparse(base_url)
    replacements = {
        "{{BaseURL}}": base_url.rstrip("/"),
        "{{base_url}}": base_url.rstrip("/"),
        "{{Hostname}}": parsed.netloc,
        "{{hostname}}": parsed.netloc,
    }
    rendered = str(value)
    for needle, replacement in replacements.items():
        rendered = rendered.replace(needle, replacement)
    return rendered


__all__ = [
    "ExtractedValue",
    "MatchResult",
    "SAFE_HTTP_METHODS",
    "SUPPORTED_HTTP_METHODS",
    "StealthixTemplate",
    "TemplateEvaluation",
    "TemplateExtractor",
    "TemplateHttpRequest",
    "TemplateMatcher",
    "TemplateResponse",
    "TemplateValidationError",
    "evaluate_template",
    "load_stealthix_template",
    "request_specs_for_template",
]
