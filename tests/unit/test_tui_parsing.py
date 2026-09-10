from __future__ import annotations

from stealthix._tui_runtime.parsing import config_from_tui_params


def test_tui_parsing_infers_base_url_from_api_schema_and_preserves_phase7_fields(tmp_path):
    schema_path = tmp_path / "openapi.yaml"
    schema_path.write_text(
        """
openapi: 3.0.0
servers:
  - url: https://api.example.test
paths:
  /users:
    get: {}
""",
        encoding="utf-8",
    )

    config = config_from_tui_params(
        {
            "api_schema": str(schema_path),
            "api_schema_format": "auto",
            "api_header_param": "X-Tenant, X-Trace",
            "ws_message": '{"ping":1}\n{"ping":2}',
            "ws_header": "X-WS: 1\nX-Mode: test",
            "ws_subprotocol": "graphql-ws, chat",
            "ws_timeout": 12,
            "method": "PATCH",
            "body_format": "json",
            "body": '{"name":"alice"}',
        }
    )

    assert config.base_url == "https://api.example.test"
    assert config.api_header_params == ["X-Tenant", "X-Trace"]
    assert config.ws_messages == ['{"ping":1}', '{"ping":2}']
    assert config.ws_headers == {"X-WS": "1", "X-Mode": "test"}
    assert config.ws_subprotocols == ["graphql-ws", "chat"]
    assert config.ws_timeout == 12.0
    assert config.data == {"name": "alice"}


def test_tui_parsing_falls_back_to_ws_url_when_http_url_missing():
    config = config_from_tui_params(
        {"ws_url": "wss://socket.example.test/ws", "ws_message": '{"ping":1}'}
    )

    assert config.base_url == "wss://socket.example.test/ws"
    assert config.ws_url == "wss://socket.example.test/ws"
    assert config.ws_messages == ['{"ping":1}']
