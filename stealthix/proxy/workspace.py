from __future__ import annotations

import json
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import yaml

from stealthix.workflows.requests import RequestSpec, import_har, normalize_request_spec

ProxyAction = Literal["forward", "drop", "edit"]
InterceptState = Literal["pending", "forwarded", "dropped", "edited"]


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _jsonable(value: Any) -> Any:
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        if isinstance(value, dict):
            return {str(key): _jsonable(item) for key, item in value.items()}
        if isinstance(value, (list, tuple, set)):
            return [_jsonable(item) for item in value]
        return str(value)


def _excerpt(value: Any, *, limit: int = 4096) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    else:
        text = str(value)
    return text if len(text) <= limit else f"{text[: limit - 3]}..."


def request_spec_to_dict(spec: RequestSpec) -> dict[str, Any]:
    return {
        "method": spec.method,
        "url": spec.url,
        "headers": dict(spec.headers),
        "cookies": dict(spec.cookies),
        "data": _jsonable(spec.data),
        "body_format": spec.body_format,
        "raw_body": spec.raw_body,
        "target_params": list(spec.target_params or []),
        "metadata": _jsonable(dict(spec.metadata)),
    }


def request_spec_from_dict(payload: dict[str, Any]) -> RequestSpec:
    return RequestSpec(
        method=str(payload.get("method") or "GET").upper(),
        url=str(payload["url"]),
        headers={str(key): str(value) for key, value in dict(payload.get("headers") or {}).items()},
        cookies={str(key): str(value) for key, value in dict(payload.get("cookies") or {}).items()},
        data=payload.get("data"),
        body_format=str(payload.get("body_format") or "form"),
        raw_body=payload.get("raw_body"),
        target_params=[str(item) for item in payload.get("target_params") or []] or None,
        metadata=dict(payload.get("metadata") or {}),
    )


def captured_exchange_from_history_entry(entry: dict[str, Any]) -> CapturedExchange:
    metadata = dict(entry.get("metadata") or {})
    request_headers = {
        str(key): str(value) for key, value in dict(metadata.get("request_headers") or {}).items()
    }
    request = normalize_request_spec(
        method=str(entry.get("method") or metadata.get("method") or "GET"),
        url=str(entry["url"]),
        headers=request_headers,
        body=metadata.get("request_body") or None,
        metadata={"origin": "request-history", "history_metadata": metadata},
    )
    response = CapturedResponse(
        status_code=_status_code(entry.get("status") or metadata.get("status_code")),
        headers={
            str(key): str(value) for key, value in dict(metadata.get("headers") or {}).items()
        },
        body=metadata.get("response_excerpt"),
        elapsed=float(entry["elapsed"]) if entry.get("elapsed") is not None else None,
        content_type=metadata.get("content_type"),
        metadata={
            "history_status": entry.get("status"),
            "transport": metadata.get("transport"),
            "cached": bool(metadata.get("cached")),
        },
    )
    return CapturedExchange(
        id=f"px-{uuid.uuid4().hex}",
        request=request,
        response=response,
        created_at=str(entry.get("timestamp") or _utc_now()),
        updated_at=str(entry.get("timestamp") or _utc_now()),
        source="request-history",
        metadata={"history_entry": _jsonable(entry)},
    )


@dataclass(frozen=True)
class CapturedResponse:
    status_code: int | None = None
    headers: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    elapsed: float | None = None
    content_type: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status_code": self.status_code,
            "headers": dict(self.headers),
            "body": self.body,
            "body_excerpt": _excerpt(self.body),
            "elapsed": self.elapsed,
            "content_type": self.content_type or _header_value(self.headers, "content-type"),
            "metadata": _jsonable(dict(self.metadata)),
        }

    @staticmethod
    def from_dict(payload: dict[str, Any] | None) -> CapturedResponse | None:
        if not payload:
            return None
        status = payload.get("status_code")
        return CapturedResponse(
            status_code=int(status) if status is not None else None,
            headers={
                str(key): str(value) for key, value in dict(payload.get("headers") or {}).items()
            },
            body=payload.get("body"),
            elapsed=float(payload["elapsed"]) if payload.get("elapsed") is not None else None,
            content_type=payload.get("content_type"),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class CapturedExchange:
    id: str
    request: RequestSpec
    response: CapturedResponse | None = None
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    source: str = "manual"
    tags: tuple[str, ...] = ()
    note: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_updates(self, **updates: Any) -> CapturedExchange:
        return replace(self, updated_at=_utc_now(), **updates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "source": self.source,
            "tags": list(self.tags),
            "note": self.note,
            "metadata": _jsonable(dict(self.metadata)),
            "request": request_spec_to_dict(self.request),
            "response": self.response.to_dict() if self.response else None,
        }

    @staticmethod
    def from_dict(payload: dict[str, Any]) -> CapturedExchange:
        return CapturedExchange(
            id=str(payload["id"]),
            request=request_spec_from_dict(dict(payload["request"])),
            response=CapturedResponse.from_dict(payload.get("response")),
            created_at=str(payload.get("created_at") or _utc_now()),
            updated_at=str(payload.get("updated_at") or payload.get("created_at") or _utc_now()),
            source=str(payload.get("source") or "manual"),
            tags=tuple(str(item) for item in payload.get("tags") or []),
            note=str(payload.get("note") or ""),
            metadata=dict(payload.get("metadata") or {}),
        )


@dataclass(frozen=True)
class ProxySearch:
    query: str | None = None
    method: str | None = None
    status: int | str | None = None
    tag: str | None = None
    host: str | None = None
    limit: int | None = None


@dataclass(frozen=True)
class InterceptionRule:
    id: str
    methods: tuple[str, ...] = ()
    url_contains: str | None = None
    host: str | None = None
    tag: str | None = None
    enabled: bool = True

    def matches(self, record: CapturedExchange) -> bool:
        if not self.enabled:
            return False
        if self.methods and record.request.method.upper() not in {
            item.upper() for item in self.methods
        }:
            return False
        if self.url_contains and self.url_contains not in record.request.url:
            return False
        if self.host and urlparse(record.request.url).hostname != self.host:
            return False
        if self.tag and self.tag not in record.tags:
            return False
        return True


@dataclass(frozen=True)
class InterceptedExchange:
    id: str
    record_id: str
    record: CapturedExchange
    rule_id: str | None = None
    state: InterceptState = "pending"
    created_at: str = field(default_factory=_utc_now)
    updated_at: str = field(default_factory=_utc_now)
    note: str = ""

    def with_updates(self, **updates: Any) -> InterceptedExchange:
        return replace(self, updated_at=_utc_now(), **updates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "record_id": self.record_id,
            "rule_id": self.rule_id,
            "state": self.state,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "note": self.note,
            "record": self.record.to_dict(),
        }


class InterceptionQueue:
    def __init__(
        self,
        *,
        rules: Iterable[InterceptionRule] | None = None,
        workspace: ProxyWorkspace | None = None,
    ) -> None:
        self.rules = list(rules or [])
        self.workspace = workspace
        self._pending: dict[str, InterceptedExchange] = {}
        self._resolved: list[InterceptedExchange] = []

    def offer(self, record: CapturedExchange) -> InterceptedExchange | None:
        rule = next((item for item in self.rules if item.matches(record)), None)
        if self.rules and rule is None:
            return None
        item = InterceptedExchange(
            id=f"int-{uuid.uuid4().hex}",
            record_id=record.id,
            record=record,
            rule_id=rule.id if rule else None,
        )
        self._pending[item.id] = item
        return item

    def pending(self) -> list[InterceptedExchange]:
        return list(self._pending.values())

    def resolved(self) -> list[InterceptedExchange]:
        return list(self._resolved)

    def resolve(
        self,
        intercept_id: str,
        *,
        action: ProxyAction,
        edited_request: RequestSpec | None = None,
        note: str = "",
    ) -> InterceptedExchange:
        item = self._pending[intercept_id]
        record = item.record
        metadata = {
            **record.metadata,
            "interception": {
                "action": action,
                "resolved_at": _utc_now(),
                "note": note,
                "rule_id": item.rule_id,
            },
        }
        state: InterceptState
        if action == "edit":
            if edited_request is None:
                raise ValueError("edited_request is required when action='edit'")
            record = record.with_updates(request=edited_request, metadata=metadata)
            state = "edited"
        elif action == "drop":
            record = record.with_updates(metadata=metadata)
            state = "dropped"
        elif action == "forward":
            record = record.with_updates(metadata=metadata)
            state = "forwarded"
        else:
            raise ValueError("action must be one of: forward, drop, edit")
        self._pending.pop(intercept_id)
        if self.workspace:
            self.workspace.upsert(record)
        resolved = item.with_updates(record=record, state=state, note=note)
        self._resolved.append(resolved)
        return resolved


class ProxyWorkspace:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.history_path = self.root / "history.jsonl"
        self.root.mkdir(parents=True, exist_ok=True)
        self._records: dict[str, CapturedExchange] = {}
        self._load()

    def _load(self) -> None:
        if not self.history_path.exists():
            return
        for line in self.history_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            record = CapturedExchange.from_dict(json.loads(line))
            self._records[record.id] = record

    def _persist(self) -> None:
        tmp = self.history_path.with_suffix(".jsonl.tmp")
        tmp.write_text(
            "".join(
                json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False) + "\n"
                for record in self._records.values()
            ),
            encoding="utf-8",
        )
        tmp.replace(self.history_path)

    def upsert(self, record: CapturedExchange) -> CapturedExchange:
        self._records[record.id] = record
        self._persist()
        return record

    def capture_request(
        self,
        request: RequestSpec,
        *,
        source: str | None = None,
        tags: Iterable[str] | None = None,
        note: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> CapturedExchange:
        record = CapturedExchange(
            id=f"px-{uuid.uuid4().hex}",
            request=request,
            source=source or str(request.metadata.get("origin") or "manual"),
            tags=tuple(dict.fromkeys(str(tag) for tag in tags or [] if str(tag).strip())),
            note=note,
            metadata=dict(metadata or {}),
        )
        return self.upsert(record)

    def capture_exchange(
        self,
        request: RequestSpec,
        *,
        response: CapturedResponse | None = None,
        status_code: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str | bytes | None = None,
        elapsed: float | None = None,
        source: str | None = None,
        tags: Iterable[str] | None = None,
        note: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> CapturedExchange:
        captured_response = response
        if captured_response is None and (
            status_code is not None
            or response_headers
            or response_body is not None
            or elapsed is not None
        ):
            captured_response = CapturedResponse(
                status_code=status_code,
                headers={str(k): str(v) for k, v in dict(response_headers or {}).items()},
                body=_excerpt(response_body, limit=2_000_000)
                if response_body is not None
                else None,
                elapsed=elapsed,
            )
        record = self.capture_request(
            request,
            source=source,
            tags=tags,
            note=note,
            metadata=metadata,
        )
        if captured_response is None:
            return record
        return self.upsert(record.with_updates(response=captured_response))

    def update_response(
        self,
        record_id: str,
        response: CapturedResponse,
    ) -> CapturedExchange:
        return self.upsert(self.get(record_id).with_updates(response=response))

    def update_request(self, record_id: str, request: RequestSpec) -> CapturedExchange:
        return self.upsert(self.get(record_id).with_updates(request=request))

    def get(self, record_id: str) -> CapturedExchange:
        return self._records[record_id]

    def records(self) -> list[CapturedExchange]:
        return list(self._records.values())

    def search(
        self,
        query: str | ProxySearch | None = None,
        *,
        method: str | None = None,
        status: int | str | None = None,
        tag: str | None = None,
        host: str | None = None,
        limit: int | None = None,
    ) -> list[CapturedExchange]:
        criteria = (
            query
            if isinstance(query, ProxySearch)
            else ProxySearch(
                query=query, method=method, status=status, tag=tag, host=host, limit=limit
            )
        )
        results = [record for record in self._records.values() if _matches(record, criteria)]
        return results[: criteria.limit] if criteria.limit is not None else results

    def import_records(self, records: Iterable[CapturedExchange]) -> list[CapturedExchange]:
        imported = []
        for record in records:
            imported.append(self.upsert(record))
        return imported

    def import_request_history(self, entries: Iterable[dict[str, Any]]) -> list[CapturedExchange]:
        return self.import_records(captured_exchange_from_history_entry(entry) for entry in entries)

    def import_payload(
        self, payload: dict[str, Any] | list[dict[str, Any]]
    ) -> list[CapturedExchange]:
        raw_records = payload.get("records", []) if isinstance(payload, dict) else payload
        return self.import_records(CapturedExchange.from_dict(item) for item in raw_records)

    def import_file(self, path: str | Path) -> list[CapturedExchange]:
        source = Path(path)
        text = source.read_text(encoding="utf-8")
        if source.suffix.lower() in {".har"}:
            return self.import_har(json.loads(text))
        if source.suffix.lower() in {".yaml", ".yml"}:
            loaded = yaml.safe_load(text)
            return self.import_payload(loaded or {})
        if source.suffix.lower() == ".jsonl":
            return self.import_payload(
                [json.loads(line) for line in text.splitlines() if line.strip()]
            )
        return self.import_payload(json.loads(text))

    def import_har(self, source: str | Path | dict[str, Any]) -> list[CapturedExchange]:
        document = _load_har_document(source)
        specs = import_har(document)
        entries = document.get("log", {}).get("entries", [])
        records: list[CapturedExchange] = []
        for index, spec in enumerate(specs):
            response = _har_response(entries[index] if index < len(entries) else {})
            records.append(
                self.capture_exchange(
                    spec,
                    response=response,
                    source="har",
                    metadata={"har_entry_index": index},
                )
            )
        return records

    def export_payload(self, *, format: str = "json") -> str:
        normalized = format.lower()
        if normalized == "json":
            return json.dumps(
                {
                    "version": 1,
                    "exported_at": _utc_now(),
                    "records": [record.to_dict() for record in self.records()],
                },
                indent=2,
                sort_keys=True,
                ensure_ascii=False,
            )
        if normalized == "jsonl":
            return "".join(
                json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False) + "\n"
                for record in self.records()
            )
        if normalized == "yaml":
            return yaml.safe_dump(
                {
                    "version": 1,
                    "exported_at": _utc_now(),
                    "records": [record.to_dict() for record in self.records()],
                },
                sort_keys=True,
                allow_unicode=True,
            )
        if normalized == "har":
            return json.dumps(
                _har_export(self.records()), indent=2, sort_keys=True, ensure_ascii=False
            )
        raise ValueError("format must be one of: json, jsonl, yaml, har")

    def stats(self) -> dict[str, Any]:
        records = self.records()
        return {
            "workspace": str(self.root),
            "history_path": str(self.history_path),
            "record_count": len(records),
            "response_count": sum(1 for record in records if record.response is not None),
            "methods": _counts(record.request.method for record in records),
            "statuses": _counts(
                str(record.response.status_code)
                for record in records
                if record.response and record.response.status_code is not None
            ),
        }


def _matches(record: CapturedExchange, criteria: ProxySearch) -> bool:
    if criteria.method and record.request.method.upper() != criteria.method.upper():
        return False
    if criteria.status is not None:
        expected = str(criteria.status)
        actual = str(record.response.status_code) if record.response else ""
        if actual != expected:
            return False
    if criteria.tag and criteria.tag not in record.tags:
        return False
    if criteria.host and urlparse(record.request.url).hostname != criteria.host:
        return False
    if criteria.query:
        haystack = json.dumps(record.to_dict(), sort_keys=True, ensure_ascii=False).lower()
        if criteria.query.lower() not in haystack:
            return False
    return True


def _counts(values: Iterable[str]) -> dict[str, int]:
    output: dict[str, int] = {}
    for value in values:
        output[value] = output.get(value, 0) + 1
    return output


def _status_code(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _header_value(headers: dict[str, str], name: str) -> str | None:
    lowered = name.lower()
    for key, value in headers.items():
        if key.lower() == lowered:
            return value
    return None


def _har_pairs(items: Any) -> dict[str, str]:
    if not isinstance(items, list):
        return {}
    output: dict[str, str] = {}
    for item in items:
        if isinstance(item, dict) and item.get("name"):
            output[str(item["name"])] = str(item.get("value") or "")
    return output


def _load_har_document(source: str | Path | dict[str, Any]) -> dict[str, Any]:
    if isinstance(source, dict):
        return source
    text = Path(source).read_text(encoding="utf-8")
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("HAR source must decode to an object")
    return document


def _har_response(entry: Any) -> CapturedResponse | None:
    response = entry.get("response") if isinstance(entry, dict) else None
    if not isinstance(response, dict):
        return None
    content = response.get("content") if isinstance(response.get("content"), dict) else {}
    body = content.get("text") if isinstance(content, dict) else None
    status = response.get("status")
    elapsed_ms = entry.get("time") if isinstance(entry, dict) else None
    return CapturedResponse(
        status_code=int(status) if status is not None else None,
        headers=_har_pairs(response.get("headers")),
        body=str(body) if body is not None else None,
        elapsed=float(elapsed_ms) / 1000 if elapsed_ms is not None else None,
        content_type=str(content.get("mimeType"))
        if isinstance(content, dict) and content.get("mimeType")
        else None,
    )


def _har_export(records: list[CapturedExchange]) -> dict[str, Any]:
    entries = []
    for record in records:
        parsed = urlparse(record.request.url)
        request_headers = [
            {"name": key, "value": value} for key, value in record.request.headers.items()
        ]
        response = record.response
        response_headers = [
            {"name": key, "value": value}
            for key, value in (response.headers.items() if response else [])
        ]
        body = response.body if response and response.body is not None else ""
        entries.append(
            {
                "startedDateTime": record.created_at,
                "time": int((response.elapsed or 0) * 1000) if response else 0,
                "request": {
                    "method": record.request.method,
                    "url": record.request.url,
                    "httpVersion": "HTTP/1.1",
                    "headers": request_headers,
                    "queryString": [
                        {"name": key, "value": value}
                        for key, value in _query_pairs(parsed.query).items()
                    ],
                    "cookies": [
                        {"name": key, "value": value}
                        for key, value in record.request.cookies.items()
                    ],
                    "headersSize": -1,
                    "bodySize": len(record.request.raw_body or ""),
                },
                "response": {
                    "status": response.status_code if response else 0,
                    "statusText": "",
                    "httpVersion": "HTTP/1.1",
                    "headers": response_headers,
                    "cookies": [],
                    "content": {
                        "size": len(body),
                        "mimeType": response.content_type if response else "",
                        "text": body,
                    },
                    "redirectURL": "",
                    "headersSize": -1,
                    "bodySize": len(body),
                },
                "cache": {},
                "timings": {
                    "send": 0,
                    "wait": int((response.elapsed or 0) * 1000) if response else 0,
                    "receive": 0,
                },
                "_stealthix": {"id": record.id, "source": record.source, "tags": list(record.tags)},
            }
        )
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "Stealthix", "version": "0.1.0"},
            "entries": entries,
        }
    }


def _query_pairs(query: str) -> dict[str, str]:
    from urllib.parse import parse_qsl

    return dict(parse_qsl(query, keep_blank_values=True))


__all__ = [
    "CapturedExchange",
    "CapturedResponse",
    "InterceptedExchange",
    "InterceptionQueue",
    "InterceptionRule",
    "ProxySearch",
    "ProxyWorkspace",
    "captured_exchange_from_history_entry",
    "request_spec_from_dict",
    "request_spec_to_dict",
]
