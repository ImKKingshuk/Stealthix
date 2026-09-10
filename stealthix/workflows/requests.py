from __future__ import annotations

import json
import shlex
from dataclasses import dataclass, field, replace
from os import PathLike
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import yaml

_BODY_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_DROP_REPLAY_HEADERS = {"host", "content-length", "cookie"}


@dataclass(frozen=True)
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    data: Any | None = None
    body_format: str = "form"
    raw_body: str | None = None
    target_params: list[str] | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_scan_target(self) -> dict[str, Any]:
        target = {
            "url": self.url,
            "method": self.method,
            "headers": dict(self.headers),
            "data": self.data,
            "body_format": self.body_format,
            "target_params": list(self.target_params or []) or None,
            "metadata": dict(self.metadata),
        }
        if self.cookies:
            target["cookies"] = dict(self.cookies)
        return target

    def with_updates(self, **updates: Any) -> RequestSpec:
        return replace(self, **updates)


def normalize_request_spec(
    *,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str | bytes | None = None,
    metadata: dict[str, Any] | None = None,
) -> RequestSpec:
    request_headers, request_cookies = _normalize_headers(headers or {})
    if cookies:
        request_cookies.update({str(k): str(v) for k, v in cookies.items()})
    content_type = _header_value(headers or {}, "content-type")
    raw_body = _decode_body(body)
    body_format, data = _coerce_body(raw_body, content_type=content_type)
    params = _target_params(url, data if isinstance(data, dict) else None)
    return RequestSpec(
        method=str(method or "GET").upper(),
        url=_ensure_url(url),
        headers=request_headers,
        cookies=request_cookies,
        data=data,
        body_format=body_format,
        raw_body=raw_body,
        target_params=params or None,
        metadata={**(metadata or {}), "content_type": content_type or None},
    )


def import_raw_http(raw_request: str, *, default_scheme: str = "http") -> RequestSpec:
    head, sep, body = raw_request.replace("\r\n", "\n").partition("\n\n")
    lines = [line for line in head.split("\n") if line.strip()]
    if not lines:
        raise ValueError("raw HTTP request is empty")
    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError("raw HTTP request line must contain method and target")
    method, target = parts[0].upper(), parts[1]
    headers = _parse_header_lines(lines[1:])
    host = _header_value(headers, "host")
    if target.startswith(("http://", "https://")):
        url = target
    elif host:
        url = f"{default_scheme}://{host}{target if target.startswith('/') else '/' + target}"
    else:
        raise ValueError("relative raw HTTP request requires a Host header")
    return normalize_request_spec(
        method=method,
        url=url,
        headers=headers,
        body=body if sep else None,
        metadata={"origin": "raw-http"},
    )


def import_curl(curl_command: str) -> RequestSpec:
    tokens = shlex.split(curl_command)
    if tokens and tokens[0] == "curl":
        tokens = tokens[1:]
    method: str | None = None
    headers: dict[str, str] = {}
    cookies: dict[str, str] = {}
    body_parts: list[str] = []
    url = ""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        key, inline = _split_option(token)
        if key in {"-X", "--request"}:
            value, index = _option_value(tokens, index, inline)
            method = value.upper()
        elif key in {"-H", "--header"}:
            value, index = _option_value(tokens, index, inline)
            _add_header(headers, value)
        elif key in {"-d", "--data", "--data-raw", "--data-binary", "--data-urlencode"}:
            value, index = _option_value(tokens, index, inline)
            body_parts.append(value)
            method = method or "POST"
        elif key in {"-b", "--cookie"}:
            value, index = _option_value(tokens, index, inline)
            cookies.update(_parse_cookie_header(value))
        elif token.startswith("-"):
            if key in _OPTIONS_WITH_IGNORED_VALUE:
                _value, index = _option_value(tokens, index, inline)
        elif not url:
            url = token
        index += 1
    if not url:
        raise ValueError("curl command does not contain a URL")
    body = "&".join(body_parts) if body_parts else None
    return normalize_request_spec(
        method=method or "GET",
        url=url,
        headers=headers,
        cookies=cookies,
        body=body,
        metadata={"origin": "curl"},
    )


def import_har(source: str | Path | dict[str, Any]) -> list[RequestSpec]:
    document = _load_har(source)
    entries = document.get("log", {}).get("entries", [])
    if not isinstance(entries, list):
        raise ValueError("HAR log.entries must be a list")
    specs: list[RequestSpec] = []
    for entry in entries:
        request = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(request, dict):
            continue
        method = str(request.get("method") or "GET").upper()
        url = _har_url(request)
        headers = _har_pairs(request.get("headers"))
        post_data = request.get("postData") if isinstance(request.get("postData"), dict) else {}
        body = _har_post_body(post_data)
        spec = normalize_request_spec(
            method=method,
            url=url,
            headers=headers,
            body=body,
            metadata={"origin": "har"},
        )
        if isinstance(post_data, dict) and isinstance(post_data.get("params"), list):
            params = _har_pairs(post_data.get("params"))
            if params:
                spec = spec.with_updates(data=params, body_format="form")
        specs.append(spec)
    return specs


def _ensure_url(url: str) -> str:
    parsed = urlparse(str(url).strip())
    if parsed.scheme and parsed.netloc:
        return str(url).strip()
    raise ValueError(f"request URL must be absolute: {url}")


def _decode_body(body: str | bytes | None) -> str | None:
    if body is None:
        return None
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="replace")
    return str(body)


def _coerce_body(body: str | None, *, content_type: str | None) -> tuple[str, Any | None]:
    if body in (None, ""):
        return "form", None
    lowered = str(content_type or "").lower()
    text = str(body)
    if "json" in lowered or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
            return "json", parsed if isinstance(parsed, dict) else {"payload": parsed}
        except json.JSONDecodeError:
            return "json", {"payload": text}
    if "xml" in lowered or text.lstrip().startswith("<"):
        return "xml", text
    if "x-www-form-urlencoded" in lowered or "=" in text:
        parsed = parse_qs(text, keep_blank_values=True)
        return "form", {
            key: values[0] if len(values) == 1 else values for key, values in parsed.items()
        }
    return "form", {"payload": text}


def _normalize_headers(headers: dict[str, str]) -> tuple[dict[str, str], dict[str, str]]:
    normalized: dict[str, str] = {}
    cookies: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).strip()
        if not name:
            continue
        lowered = name.lower()
        if lowered == "cookie":
            cookies.update(_parse_cookie_header(str(value)))
            continue
        if lowered in _DROP_REPLAY_HEADERS:
            continue
        normalized[name] = str(value)
    return normalized, cookies


def _parse_header_lines(lines: list[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in lines:
        _add_header(headers, line)
    return headers


def _add_header(headers: dict[str, str], line: str) -> None:
    if ":" not in line:
        return
    name, value = line.split(":", 1)
    name = name.strip()
    if name:
        headers[name] = value.strip()


def _header_value(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if str(key).lower() == lowered:
            return str(value)
    return None


def _parse_cookie_header(value: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for item in str(value or "").split(";"):
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        key = key.strip()
        if key:
            cookies[key] = val.strip()
    return cookies


def _target_params(url: str, data: dict[str, Any] | None) -> list[str]:
    params = [str(key) for key in parse_qs(urlparse(url).query).keys() if str(key).strip()]
    if data:
        params.extend(str(key) for key in data.keys() if str(key).strip())
    return list(dict.fromkeys(params))


def _split_option(token: str) -> tuple[str, str | None]:
    if token.startswith("--") and "=" in token:
        key, value = token.split("=", 1)
        return key, value
    return token, None


def _option_value(tokens: list[str], index: int, inline: str | None) -> tuple[str, int]:
    if inline is not None:
        return inline, index
    if index + 1 >= len(tokens):
        raise ValueError(f"missing value for {tokens[index]}")
    return tokens[index + 1], index + 1


_OPTIONS_WITH_IGNORED_VALUE = {
    "-A",
    "--user-agent",
    "--connect-timeout",
    "--max-time",
    "-o",
    "--output",
    "-u",
    "--user",
}


def _load_har(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    text = _source_text(source)
    parsed = json.loads(text)
    if not isinstance(parsed, dict):
        raise ValueError("HAR source must decode to an object")
    return parsed


def _har_url(request: dict[str, Any]) -> str:
    url = str(request.get("url") or "").strip()
    query_pairs = _har_pairs(request.get("queryString"))
    if not query_pairs:
        return _ensure_url(url)
    parsed = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in query_pairs.items():
        existing[str(key)] = [str(value)]
    return urlunparse(parsed._replace(query=urlencode(existing, doseq=True, safe=":/%")))


def _har_pairs(items: Any) -> dict[str, str]:
    if not isinstance(items, list):
        return {}
    output: dict[str, str] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or item.get("key") or "").strip()
        if name:
            output[name] = str(item.get("value") or "")
    return output


def _har_post_body(post_data: dict[str, Any]) -> str | None:
    if not isinstance(post_data, dict):
        return None
    text = post_data.get("text")
    if text is not None:
        return str(text)
    params = _har_pairs(post_data.get("params"))
    return urlencode(params) if params else None


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


__all__ = [
    "RequestSpec",
    "import_curl",
    "import_har",
    "import_raw_http",
    "normalize_request_spec",
]
