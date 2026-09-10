from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

import yaml

from stealthix.core.models import TargetParam
from stealthix.core.session import ScanSession

API_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")
BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_HEADER_SKIP = {"authorization", "cookie", "host", "content-length"}
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.IGNORECASE
)


def method_uses_body(method: str | None) -> bool:
    return str(method or "GET").upper() in BODY_METHODS


def classify_scalar(value: Any) -> str:
    if value is None:
        return "string"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, (int, float)):
        return "number"
    text = str(value).strip()
    if text.isdigit():
        return "number"
    if text.lower() in {"true", "false"}:
        return "bool"
    return "string"


def _content_type_to_body_format(content_type: str) -> str:
    lowered = str(content_type or "").lower()
    if "json" in lowered:
        return "json"
    if "xml" in lowered:
        return "xml"
    return "form"


def _flatten_fields(value: Any, *, prefix: str = "") -> list[tuple[str, Any]]:
    output: list[tuple[str, Any]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            output.extend(_flatten_fields(child, prefix=name))
        return output
    if isinstance(value, list):
        if not value:
            output.append((prefix, ""))
            return output
        for index, child in enumerate(value):
            name = f"{prefix}[{index}]" if prefix else f"[{index}]"
            output.extend(_flatten_fields(child, prefix=name))
        return output
    output.append((prefix or "payload", value))
    return output


def _safe_sample(
    name: str = "value", schema_type: str | None = None, schema_format: str | None = None
) -> Any:
    if schema_format == "uuid":
        return "11111111-1111-1111-1111-111111111111"
    if schema_format == "date-time":
        return "2026-03-11T00:00:00Z"
    if schema_format == "date":
        return "2026-03-11"
    if schema_type == "integer":
        return 1
    if schema_type == "number":
        return 1
    if schema_type == "boolean":
        return True
    if name.lower().endswith("id"):
        return 1
    return "sample"


def _resolve_ref(document: dict[str, Any], schema: dict[str, Any]) -> dict[str, Any]:
    ref = schema.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return schema
    current: Any = document
    for part in ref[2:].split("/"):
        if not isinstance(current, dict):
            return schema
        current = current.get(part)
    return current if isinstance(current, dict) else schema


def _schema_example(
    document: dict[str, Any], schema: dict[str, Any] | None, *, field_name: str = "value"
) -> Any:
    if not isinstance(schema, dict):
        return _safe_sample(field_name)
    schema = _resolve_ref(document, schema)
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    schema_type = str(schema.get("type") or "string").lower()
    schema_format = str(schema.get("format") or "").lower() or None
    if schema_type == "object":
        properties = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        properties = properties if isinstance(properties, dict) else {}
        return {
            key: _schema_example(document, value, field_name=str(key))
            for key, value in properties.items()
        }
    if schema_type == "array":
        return [
            _schema_example(
                document,
                schema.get("items") if isinstance(schema.get("items"), dict) else {},
                field_name=field_name,
            )
        ]
    return _safe_sample(field_name, schema_type=schema_type, schema_format=schema_format)


def _load_document(source: str) -> tuple[dict[str, Any], str]:
    path = Path(source)
    text = path.read_text(encoding="utf-8") if path.exists() else source
    try:
        parsed = json.loads(text)
        return parsed if isinstance(parsed, dict) else {}, text
    except json.JSONDecodeError:
        parsed = yaml.safe_load(text)
        return parsed if isinstance(parsed, dict) else {}, text


def detect_schema_format(source: str, explicit_format: str | None = None) -> str:
    if explicit_format and explicit_format not in {"", "auto"}:
        return str(explicit_format).lower()
    document, _text = _load_document(source)
    if "openapi" in document or "swagger" in document:
        return "openapi"
    if document.get("info") and document.get("item"):
        return "postman"
    return "openapi"


def _walk_postman_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("request"), dict):
            output.append(item)
        nested = item.get("item") if isinstance(item.get("item"), list) else []
        output.extend(_walk_postman_items(cast(list[dict[str, Any]], nested)))
    return output


def _postman_raw_url(url_value: Any) -> str:
    if isinstance(url_value, str):
        return url_value
    if not isinstance(url_value, dict):
        return ""
    raw = str(url_value.get("raw") or "").strip()
    if raw:
        return raw
    protocol = str(url_value.get("protocol") or "http").strip()
    host = url_value.get("host") if isinstance(url_value.get("host"), list) else []
    host_part = ".".join(str(part).strip() for part in host if str(part).strip())
    path = url_value.get("path") if isinstance(url_value.get("path"), list) else []
    path_part = "/".join(str(part).strip("/") for part in path if str(part).strip())
    query = url_value.get("query") if isinstance(url_value.get("query"), list) else []
    query_pairs = [
        (str(item.get("key") or ""), str(item.get("value") or ""))
        for item in query
        if isinstance(item, dict) and str(item.get("key") or "").strip()
    ]
    query_part = urlencode(query_pairs)
    return f"{protocol}://{host_part}/{path_part}" + (f"?{query_part}" if query_part else "")


def infer_api_base_url(
    source: str, *, schema_format: str | None = None, fallback: str | None = None
) -> str | None:
    document, _text = _load_document(source)
    detected = detect_schema_format(source, schema_format)
    if detected == "openapi":
        servers = document.get("servers") if isinstance(document.get("servers"), list) else []
        servers = servers if isinstance(servers, list) else []
        for server in servers:
            if isinstance(server, dict) and str(server.get("url") or "").strip():
                return str(server["url"]).strip()
    else:
        items = document.get("item") if isinstance(document.get("item"), list) else []
        for item in _walk_postman_items(cast(list[dict[str, Any]], items)):
            request = item.get("request") if isinstance(item.get("request"), dict) else {}
            request = request if isinstance(request, dict) else {}
            raw_url = _postman_raw_url(request.get("url") if isinstance(request, dict) else {})
            if raw_url:
                parsed = urlparse(raw_url)
                if parsed.scheme and parsed.netloc:
                    return f"{parsed.scheme}://{parsed.netloc}"
    return fallback


def _parameter_example(document: dict[str, Any], parameter: dict[str, Any]) -> Any:
    if "example" in parameter:
        return parameter["example"]
    if isinstance(parameter.get("examples"), dict):
        for item in parameter["examples"].values():
            if isinstance(item, dict) and "value" in item:
                return item["value"]
    schema = parameter.get("schema") if isinstance(parameter.get("schema"), dict) else {}
    return _schema_example(document, schema, field_name=str(parameter.get("name") or "value"))


def _build_openapi_targets(
    document: dict[str, Any], *, base_url: str | None, default_headers: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    effective_base = str(
        base_url or infer_api_base_url(json.dumps(document), schema_format="openapi") or ""
    ).strip()
    paths = document.get("paths") if isinstance(document.get("paths"), dict) else {}
    paths = paths if isinstance(paths, dict) else {}
    for raw_path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared_params = (
            path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
        )
        for method in API_METHODS:
            operation = path_item.get(method.lower())
            if not isinstance(operation, dict):
                continue
            query_params: dict[str, Any] = {}
            header_values: dict[str, str] = dict(default_headers or {})
            path_params: dict[str, Any] = {}
            header_param_names: list[str] = []
            target_params: list[str] = []
            for parameter in [
                *shared_params,
                *(
                    operation.get("parameters")
                    if isinstance(operation.get("parameters"), list)
                    else []
                ),
            ]:
                if not isinstance(parameter, dict):
                    continue
                if "$ref" in parameter:
                    parameter = _resolve_ref(document, parameter)
                name = str(parameter.get("name") or "").strip()
                where = str(parameter.get("in") or "").strip().lower()
                if not name or where not in {"path", "query", "header"}:
                    continue
                example = _parameter_example(document, parameter)
                target_params.append(name)
                if where == "path":
                    path_params[name] = example
                elif where == "query":
                    query_params[name] = example
                else:
                    header_values[name] = str(example)
                    header_param_names.append(name)

            body_format = "form"
            body_data: dict[str, Any] | None = None
            multipart_fields: list[str] = []
            content_type: str | None = None
            request_body = (
                operation.get("requestBody")
                if isinstance(operation.get("requestBody"), dict)
                else None
            )
            if request_body and "$ref" in request_body:
                request_body = _resolve_ref(document, request_body)
            if request_body:
                content = (
                    request_body.get("content")
                    if isinstance(request_body.get("content"), dict)
                    else {}
                )
                chosen_type = next(
                    (
                        item
                        for item in (
                            "application/json",
                            "application/xml",
                            "text/xml",
                            "application/x-www-form-urlencoded",
                            "multipart/form-data",
                        )
                        if isinstance(content, dict) and item in content
                    ),
                    next(iter(content.keys())) if isinstance(content, dict) else None,
                )
                if (
                    chosen_type
                    and isinstance(content, dict)
                    and isinstance(content.get(chosen_type), dict)
                ):
                    content_type = chosen_type
                    media = content.get(chosen_type) if isinstance(content, dict) else {}
                    body_format = _content_type_to_body_format(chosen_type)
                    schema = (
                        media.get("schema")
                        if isinstance(media, dict) and isinstance(media.get("schema"), dict)
                        else {}
                    )
                    example = (
                        media.get("example")
                        if isinstance(media, dict) and "example" in media
                        else _schema_example(document, schema)
                    )
                    body_data = example if isinstance(example, dict) else {"payload": example}
                    if (
                        chosen_type == "multipart/form-data"
                        and isinstance(schema, dict)
                        and isinstance(schema.get("properties"), dict)
                    ):
                        for key, value in schema.get("properties", {}).items():
                            if isinstance(value, dict) and str(
                                value.get("format") or ""
                            ).lower() in {"binary", "base64"}:
                                multipart_fields.append(str(key))
                    target_params.extend(name for name, _value in _flatten_fields(body_data))

            template_url = (
                urljoin(effective_base.rstrip("/") + "/", str(raw_path).lstrip("/"))
                if effective_base
                else str(raw_path)
            )
            concrete_url = template_url
            for name, value in path_params.items():
                concrete_url = concrete_url.replace("{" + name + "}", str(value))
            parsed = urlparse(concrete_url)
            merged_query = dict(parse_qs(parsed.query))
            for name, value in query_params.items():
                merged_query[str(name)] = [str(value)]
            final_url = urlunparse(
                parsed._replace(query=urlencode(merged_query, doseq=True, safe=":/%{}"))
            )
            metadata = {
                "origin": "api-schema-openapi",
                "path_template": template_url,
                "api_path_params": dict(path_params),
                "api_header_params": list(dict.fromkeys(header_param_names)),
                "operation_id": operation.get("operationId"),
                "operation_summary": operation.get("summary") or operation.get("description"),
            }
            if content_type:
                metadata["content_type"] = content_type
            if multipart_fields:
                metadata["multipart_fields"] = list(multipart_fields)
            targets.append(
                {
                    "url": final_url,
                    "method": method,
                    "headers": header_values,
                    "data": body_data,
                    "body_format": body_format,
                    "target_params": list(dict.fromkeys(target_params)) or None,
                    "metadata": metadata,
                }
            )
    return targets


def _coerce_postman_body(
    request: dict[str, Any],
) -> tuple[str, dict[str, Any] | None, list[str], str | None]:
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    body = body if isinstance(body, dict) else {}
    mode = str(body.get("mode") or "").lower() if isinstance(body, dict) else ""
    headers = request.get("header") if isinstance(request.get("header"), list) else []
    headers = headers if isinstance(headers, list) else []
    content_type = next(
        (
            str(item.get("value") or "")
            for item in headers
            if isinstance(item, dict) and str(item.get("key") or "").lower() == "content-type"
        ),
        None,
    )
    if mode == "raw":
        raw = str(body.get("raw") or "") if isinstance(body, dict) else ""
        options = body.get("options") if isinstance(body, dict) else {}
        raw_options = options.get("raw") if isinstance(options, dict) else {}
        lowered = str(
            content_type
            or (raw_options.get("language") if isinstance(raw_options, dict) else "")
            or ""
        ).lower()
        if "json" in lowered or raw.lstrip().startswith(("{", "[")):
            try:
                parsed = json.loads(raw)
                return (
                    "json",
                    parsed if isinstance(parsed, dict) else {"payload": parsed},
                    [],
                    "application/json",
                )
            except json.JSONDecodeError:
                return "json", {"payload": raw}, [], "application/json"
        if "xml" in lowered or raw.lstrip().startswith("<"):
            return "xml", {"payload": raw}, [], content_type or "application/xml"
        return "form", {"payload": raw}, [], content_type
    if mode == "urlencoded":
        urlencoded = (
            body.get("urlencoded")
            if isinstance(body, dict) and isinstance(body.get("urlencoded"), list)
            else []
        )
        urlencoded = urlencoded if isinstance(urlencoded, list) else []
        fields = {
            str(item.get("key") or ""): str(item.get("value") or "")
            for item in urlencoded
            if isinstance(item, dict) and str(item.get("key") or "").strip()
        }
        return "form", fields or None, [], "application/x-www-form-urlencoded"
    if mode == "formdata":
        fields: dict[str, Any] = {}
        multipart_fields: list[str] = []
        formdata = (
            body.get("formdata")
            if isinstance(body, dict) and isinstance(body.get("formdata"), list)
            else []
        )
        for item in formdata if isinstance(formdata, list) else []:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or "").strip()
            if not key:
                continue
            value = item.get("value") or ""
            if str(item.get("type") or "text").lower() == "file":
                value = "sample"
                multipart_fields.append(key)
            fields[key] = value
        return "form", fields or None, multipart_fields, "multipart/form-data"
    return "form", None, [], content_type


def _build_postman_targets(
    document: dict[str, Any], *, base_url: str | None, default_headers: dict[str, str] | None = None
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    items = document.get("item") if isinstance(document.get("item"), list) else []
    for item in _walk_postman_items(cast(list[dict[str, Any]], items)):
        request = item.get("request") if isinstance(item.get("request"), dict) else {}
        request = request if isinstance(request, dict) else {}
        method = str(request.get("method") or "GET").upper()
        if method not in API_METHODS:
            continue
        raw_url = _postman_raw_url(
            request.get("url") if isinstance(request.get("url"), dict) else {}
        )
        if raw_url.startswith("{{") and base_url:
            raw_url = raw_url.replace(raw_url.split("/", 1)[0], base_url.rstrip("/"), 1)
        elif raw_url.startswith("/") and base_url:
            raw_url = urljoin(base_url.rstrip("/") + "/", raw_url.lstrip("/"))
        header_values = dict(default_headers or {})
        header_param_names: list[str] = []
        headers = request.get("header") if isinstance(request.get("header"), list) else []
        for header in headers if isinstance(headers, list) else []:
            if not isinstance(header, dict) or header.get("disabled"):
                continue
            key = str(header.get("key") or "").strip()
            if not key:
                continue
            header_values[key] = str(header.get("value") or "")
            header_param_names.append(key)
        body_format, body_data, multipart_fields, content_type = _coerce_postman_body(request)
        parsed = urlparse(raw_url)
        path_segments = [segment for segment in parsed.path.split("/") if segment]
        path_template = raw_url
        path_params: dict[str, Any] = {}
        target_params: list[str] = []
        for segment in path_segments:
            if segment.startswith(":") and len(segment) > 1:
                name = segment[1:]
                path_params[name] = 1 if name.lower().endswith("id") else "sample"
                path_template = path_template.replace(segment, "{" + name + "}")
                target_params.append(name)
        for name in parse_qs(parsed.query).keys():
            target_params.append(str(name))
        if body_data:
            target_params.extend(name for name, _value in _flatten_fields(body_data))
        concrete_url = path_template
        for name, value in path_params.items():
            concrete_url = concrete_url.replace("{" + name + "}", str(value))
        metadata = {
            "origin": "api-schema-postman",
            "path_template": path_template,
            "api_path_params": dict(path_params),
            "api_header_params": list(dict.fromkeys(header_param_names)),
            "collection_item": item.get("name"),
        }
        if multipart_fields:
            metadata["multipart_fields"] = list(multipart_fields)
        if content_type:
            metadata["content_type"] = content_type
        targets.append(
            {
                "url": concrete_url,
                "method": method,
                "headers": header_values,
                "data": body_data,
                "body_format": body_format,
                "target_params": list(dict.fromkeys(target_params)) or None,
                "metadata": metadata,
            }
        )
    return targets


def import_api_targets(
    source: str,
    *,
    schema_format: str | None = None,
    base_url: str | None = None,
    default_headers: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    document, _text = _load_document(source)
    detected = detect_schema_format(source, schema_format)
    if detected == "postman":
        return _build_postman_targets(document, base_url=base_url, default_headers=default_headers)
    return _build_openapi_targets(document, base_url=base_url, default_headers=default_headers)


def _heuristic_path_params(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    output: dict[str, Any] = {}
    for index, segment in enumerate([part for part in parsed.path.split("/") if part], start=1):
        lowered = segment.lower()
        if (
            segment.isdigit()
            or _UUID_RE.match(segment)
            or (len(segment) >= 12 and all(ch in "0123456789abcdef-" for ch in lowered))
        ):
            output[f"path[{index}]"] = segment
    return output


def discover_rest_target_params(session: ScanSession) -> list[TargetParam]:
    params: list[TargetParam] = []
    parsed = urlparse(session.config.base_url)
    for name, values in parse_qs(parsed.query).items():
        params.append(
            TargetParam(
                name=str(name), location="query", type=classify_scalar(values[0] if values else "")
            )
        )
    path_params = (
        session.metadata.get("api_path_params")
        if isinstance(session.metadata.get("api_path_params"), dict)
        else _heuristic_path_params(session.config.base_url)
    )
    if isinstance(path_params, dict):
        for name, value in path_params.items():
            params.append(TargetParam(name=str(name), location="path", type=classify_scalar(value)))
    header_names: list[str] = []
    header_names.extend(
        str(item) for item in (session.config.api_header_params or []) if str(item).strip()
    )
    header_names.extend(
        str(item) for item in (session.metadata.get("api_header_params") or []) if str(item).strip()
    )
    if not header_names:
        for key in session.config.headers.keys():
            lowered = str(key).lower()
            if lowered not in _HEADER_SKIP and lowered.startswith("x-"):
                header_names.append(str(key))
    for name in dict.fromkeys(header_names):
        params.append(
            TargetParam(
                name=name,
                location="header",
                type=classify_scalar(session.config.headers.get(name, "")),
            )
        )
    if method_uses_body(session.config.method) and isinstance(session.config.data, dict):
        body_location = (
            "xml"
            if str(session.config.body_format or "").lower() == "xml"
            else ("json" if str(session.config.body_format or "").lower() == "json" else "form")
        )
        for name, value in _flatten_fields(session.config.data):
            params.append(
                TargetParam(name=name, location=body_location, type=classify_scalar(value))
            )
    deduped: list[TargetParam] = []
    seen: set[tuple[str, str]] = set()
    for item in params:
        key = (item.location, item.name)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    return deduped


def load_api_targets_for_session(session: ScanSession) -> list[dict[str, Any]]:
    source = str(session.config.api_schema or "").strip()
    if not source:
        return []
    schema_format = str(session.config.api_schema_format or "auto").lower()
    base_url = str(session.config.api_base_url or session.config.base_url or "").strip() or None
    targets = import_api_targets(
        source,
        schema_format=schema_format,
        base_url=base_url,
        default_headers=session.config.headers,
    )
    session.metadata["api_schema"] = {
        "source": source,
        "format": detect_schema_format(source, schema_format),
        "target_count": len(targets),
    }
    return targets


__all__ = [
    "API_METHODS",
    "BODY_METHODS",
    "classify_scalar",
    "detect_schema_format",
    "discover_rest_target_params",
    "import_api_targets",
    "infer_api_base_url",
    "load_api_targets_for_session",
    "method_uses_body",
]
