from __future__ import annotations

from types import SimpleNamespace

from stealthix.core.engine import Engine
from stealthix.core.http import make_request
from stealthix.core.models import ScanResult
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.core.targeting import discover_target_params
from stealthix.detection.rest_api import import_api_targets
from stealthix.detection.websocket import detect_websocket


class _DummyResponse:
    def __init__(self, status_code: int, text: str, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {"Content-Type": "application/json"}


def test_openapi_import_and_api_param_discovery(tmp_path):
    schema_path = tmp_path / "openapi.yaml"
    schema_path.write_text(
        """
openapi: 3.0.0
servers:
  - url: https://api.example.test
paths:
  /users/{userId}:
    patch:
      parameters:
        - name: userId
          in: path
          schema: {type: integer}
        - name: include
          in: query
          schema: {type: string}
        - name: X-Tenant
          in: header
          schema: {type: string}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              properties:
                profile:
                  type: object
                  properties:
                    name: {type: string}
                flags:
                  type: array
                  items: {type: string}
""",
        encoding="utf-8",
    )

    [target] = import_api_targets(str(schema_path))
    session = ScanSession(
        SessionConfig(
            base_url=target["url"],
            method=target["method"],
            headers=target["headers"],
            data=target["data"],
            body_format=target["body_format"],
        ),
        metadata=target["metadata"],
    )

    discovered = {(item.name, item.location) for item in discover_target_params(session)}

    assert target["method"] == "PATCH"
    assert ("userId", "path") in discovered
    assert ("include", "query") in discovered
    assert ("X-Tenant", "header") in discovered
    assert ("profile.name", "json") in discovered
    assert ("flags[0]", "json") in discovered


def test_openapi_import_supports_xml_request_bodies(tmp_path):
    schema_path = tmp_path / "xml-openapi.yaml"
    schema_path.write_text(
        """
openapi: 3.0.0
servers:
  - url: https://api.example.test
paths:
  /feed:
    put:
      requestBody:
        content:
          application/xml:
            schema:
              type: object
              properties:
                itemId: {type: integer}
                title: {type: string}
""",
        encoding="utf-8",
    )

    [target] = import_api_targets(str(schema_path))

    assert target["method"] == "PUT"
    assert target["body_format"] == "xml"
    assert target["metadata"]["content_type"] == "application/xml"
    assert target["data"] == {"itemId": 1, "title": "sample"}


def test_postman_import_supports_base_url_rewrite_and_multipart_fields(tmp_path):
    collection_path = tmp_path / "collection.json"
    collection_path.write_text(
        """
{
  "info": {"name": "demo", "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
  "item": [
    {
      "name": "Upload avatar",
      "request": {
        "method": "POST",
        "header": [{"key": "X-Tenant", "value": "blue"}],
        "url": {"raw": "{{baseUrl}}/users/:userId/avatar?include=meta"},
        "body": {
          "mode": "formdata",
          "formdata": [
            {"key": "avatar", "type": "file"},
            {"key": "displayName", "type": "text", "value": "alice"}
          ]
        }
      }
    }
  ]
}
""",
        encoding="utf-8",
    )

    [target] = import_api_targets(str(collection_path), base_url="https://api.example.test")

    assert target["url"] == "https://api.example.test/users/1/avatar?include=meta"
    assert target["headers"]["X-Tenant"] == "blue"
    assert target["body_format"] == "form"
    assert target["data"] == {"avatar": "sample", "displayName": "alice"}
    assert target["metadata"]["multipart_fields"] == ["avatar"]
    assert set(target["target_params"] or []) >= {"userId", "include", "avatar", "displayName"}


def test_make_request_supports_patch_json_and_runtime_header_overrides(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/api/users/1",
            method="PATCH",
            body_format="json",
            data={"name": "alice"},
        )
    )
    session.runtime["request_headers_override"] = {"X-Tenant": "red"}
    captured: dict[str, object] = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured.update(kwargs)
        return _DummyResponse(200, '{"ok":true}')

    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(request=fake_request),
    )

    body, _elapsed = make_request(session, session.config.base_url, method="POST")

    assert body == '{"ok":true}'
    assert captured["method"] == "PATCH"
    assert captured["json"] == {"name": "alice"}
    assert captured["headers"]["X-Tenant"] == "red"
    assert "request_headers_override" not in session.runtime


def test_make_request_supports_xml_payloads(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/feed",
            method="PUT",
            body_format="xml",
            data={"itemId": 7, "title": "fish & chips"},
        )
    )
    captured: dict[str, object] = {}

    def fake_request(method, url, **kwargs):
        captured["method"] = method
        captured["url"] = url
        captured.update(kwargs)
        return _DummyResponse(200, "ok", {"Content-Type": "text/plain"})

    monkeypatch.setattr("stealthix.core.http.load_rust_core", lambda: {})
    monkeypatch.setattr(
        "stealthix.core.http._get_requests_client",
        lambda _session: SimpleNamespace(request=fake_request),
    )

    body, _elapsed = make_request(session, session.config.base_url, method="POST")

    assert body == "ok"
    assert captured["method"] == "PUT"
    assert captured["headers"]["Content-Type"] == "application/xml"
    assert "<itemId>7</itemId>" in captured["data"]
    assert "fish &amp; chips" in captured["data"]


def test_detect_websocket_reports_error_and_timing_findings(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="ws://socket.example.test/ws",
            ws_url="ws://socket.example.test/ws",
            ws_messages=['{"value":"1"}'],
        )
    )

    def fake_exchange(_session, _url, message):
        if "SLEEP" in message or "sleep" in message:
            return "ok", 3.6
        if "OR" in message:
            return "SQL syntax error near '1'", 0.2
        if "$ne" in message:
            return "MongoError: bad query", 0.2
        return "ok", 0.1

    monkeypatch.setattr("stealthix.detection.websocket._exchange_message", fake_exchange)

    findings = detect_websocket(session)
    kinds = {item.kind for item in findings}

    assert "websocket-sqli" in kinds
    assert "websocket-time" in kinds
    assert session.metadata["websocket"]["enabled"] is True


def test_engine_delegates_api_schema_imports_to_scan_list(monkeypatch):
    session = ScanSession(
        SessionConfig(base_url="https://api.example.test", api_schema="schema.yaml")
    )
    captured: dict[str, object] = {}

    monkeypatch.setattr(
        "stealthix.detection.rest_api.load_api_targets_for_session",
        lambda _session: [
            {
                "url": "https://api.example.test/users/1",
                "method": "GET",
                "headers": {},
                "data": None,
                "body_format": "form",
                "target_params": ["userId"],
                "metadata": {"origin": "api-schema-openapi"},
            }
        ],
    )

    def fake_scan_list(self, specs):
        captured["specs"] = specs
        return ScanResult(target="delegated", findings=[], metadata={"delegated": True})

    monkeypatch.setattr(Engine, "scan_list", fake_scan_list)

    result = Engine(session).detect()

    assert captured["specs"][0]["url"].endswith("/users/1")
    assert result.metadata["delegated"] is True
