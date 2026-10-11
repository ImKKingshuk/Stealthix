from __future__ import annotations

import base64
import hashlib
import json
import os
import socket
import ssl
import struct
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from stealthix.core.models import Finding
from stealthix.core.session import ScanSession


def _is_ip(host: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(host)
        return True
    except (ValueError, TypeError):
        return False


@dataclass
class _Frame:
    opcode: int
    payload: bytes


class _WebSocketClient:
    def __init__(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        subprotocols: list[str] | None = None,
        timeout: float = 10.0,
        verify_tls: bool = True,
    ) -> None:
        self.url = url
        self.headers = dict(headers or {})
        self.subprotocols = list(subprotocols or [])
        self.timeout = float(timeout or 10.0)
        self.verify_tls = bool(verify_tls)
        self.sock: socket.socket | ssl.SSLSocket | None = None

    def __enter__(self) -> _WebSocketClient:
        self.connect()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def connect(self) -> None:
        parsed = urlparse(self.url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        raw_sock = socket.create_connection((host, port), timeout=self.timeout)
        raw_sock.settimeout(self.timeout)
        if parsed.scheme == "wss":
            context = ssl.create_default_context()
            if not self.verify_tls:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sni_hostname = None if (host and _is_ip(host)) else host
            self.sock = context.wrap_socket(raw_sock, server_hostname=sni_hostname)
        else:
            self.sock = raw_sock
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        request_headers = {
            "Host": f"{host}:{port}" if parsed.port else host,
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key,
            "Sec-WebSocket-Version": "13",
            **self.headers,
        }
        if self.subprotocols:
            request_headers["Sec-WebSocket-Protocol"] = ", ".join(self.subprotocols)
        handshake = "\r\n".join(
            [f"GET {path} HTTP/1.1", *[f"{k}: {v}" for k, v in request_headers.items()], "", ""]
        ).encode("utf-8")
        assert self.sock is not None
        self.sock.sendall(handshake)
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            response += chunk
        header_blob = response.decode("utf-8", errors="replace")
        status_line = header_blob.split("\r\n", 1)[0]
        if " 101 " not in f" {status_line} ":
            raise RuntimeError(f"WebSocket handshake failed: {status_line}")
        accept = ""
        for line in header_blob.split("\r\n")[1:]:
            if line.lower().startswith("sec-websocket-accept:"):
                accept = line.split(":", 1)[1].strip()
                break
        expected = base64.b64encode(
            hashlib.sha1(
                f"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11".encode("ascii"),
                usedforsecurity=False,
            ).digest()
        ).decode("ascii")
        if accept != expected:
            raise RuntimeError("Invalid WebSocket handshake accept header")

    def _read_exact(self, size: int) -> bytes:
        assert self.sock is not None
        chunks = b""
        while len(chunks) < size:
            part = self.sock.recv(size - len(chunks))
            if not part:
                raise RuntimeError("Unexpected EOF while reading WebSocket frame")
            chunks += part
        return chunks

    def send_text(self, message: str) -> None:
        assert self.sock is not None
        payload = message.encode("utf-8")
        mask_key = os.urandom(4)
        frame = bytearray([0x81])
        length = len(payload)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame.extend(struct.pack("!H", length))
        else:
            frame.append(0x80 | 127)
            frame.extend(struct.pack("!Q", length))
        frame.extend(mask_key)
        frame.extend(bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload)))
        self.sock.sendall(frame)

    def read_message(self) -> str:
        while True:
            frame = self._read_frame()
            if frame.opcode == 0x8:
                return ""
            if frame.opcode == 0x9:
                self._send_pong(frame.payload)
                continue
            if frame.opcode == 0xA:
                continue
            if frame.opcode in {0x1, 0x2}:
                return frame.payload.decode("utf-8", errors="replace")
            if frame.opcode not in {0x0, 0x1, 0x2, 0x8, 0x9, 0xA}:
                return ""

    def _send_pong(self, payload: bytes) -> None:
        assert self.sock is not None
        mask_key = os.urandom(4)
        frame = bytearray([0x8A, 0x80 | len(payload)])
        frame.extend(mask_key)
        frame.extend(bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload)))
        self.sock.sendall(frame)

    def _read_frame(self) -> _Frame:
        first, second = struct.unpack("!BB", self._read_exact(2))
        opcode = first & 0x0F
        masked = bool(second & 0x80)
        length = second & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", self._read_exact(2))
        elif length == 127:
            (length,) = struct.unpack("!Q", self._read_exact(8))
        mask_key = self._read_exact(4) if masked else b""
        payload = self._read_exact(length)
        if masked:
            payload = bytes(byte ^ mask_key[index % 4] for index, byte in enumerate(payload))
        return _Frame(opcode=opcode, payload=payload)

    def close(self) -> None:
        if self.sock is None:
            return
        try:
            self.sock.close()
        finally:
            self.sock = None


_SQL_MARKERS = [
    "sqlstate",
    "sql syntax",
    "syntax error",
    "mysql",
    "postgres",
    "sqlite",
    "odbc",
    "oracle",
]
_NOSQL_MARKERS = [
    "mongo",
    "bson",
    "$where",
    "dynamodb",
    "cassandra",
    "couchdb",
    "redis",
    "validationexception",
]


def websocket_enabled(session: ScanSession) -> bool:
    return bool(
        str(session.config.ws_url or session.config.base_url or "").startswith(("ws://", "wss://"))
    )


def _baseline_messages(session: ScanSession) -> list[str]:
    messages = [str(item) for item in (session.config.ws_messages or []) if str(item).strip()]
    return messages or ['{"action":"ping","id":1,"value":"1"}']


def _json_mutations(message: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(message)
    except json.JSONDecodeError:
        return []
    candidates = [
        ("websocket-sqli", "' OR '1'='1"),
        ("websocket-time", "' OR SLEEP(3)--"),
        ("websocket-nosqli", '{"$ne":null}'),
        ("websocket-time", '{"$where":"sleep(3000)||true"}'),
    ]
    output: list[dict[str, Any]] = []

    def walk(value: Any, prefix: str = "") -> list[tuple[str, Any]]:
        items: list[tuple[str, Any]] = []
        if isinstance(value, dict):
            for key, child in value.items():
                name = f"{prefix}.{key}" if prefix else str(key)
                items.extend(walk(child, name))
            return items
        if isinstance(value, list):
            for index, child in enumerate(value):
                name = f"{prefix}[{index}]" if prefix else f"[{index}]"
                items.extend(walk(child, name))
            return items
        items.append((prefix or "payload", value))
        return items

    def set_path(container: Any, path: str, replacement: Any) -> None:
        current = container
        tokens: list[str | int] = []
        buffer = ""
        index_buffer = ""
        in_index = False
        for char in path:
            if char == "." and not in_index:
                if buffer:
                    tokens.append(buffer)
                    buffer = ""
                continue
            if char == "[":
                if buffer:
                    tokens.append(buffer)
                    buffer = ""
                in_index = True
                index_buffer = ""
                continue
            if char == "]" and in_index:
                tokens.append(int(index_buffer))
                in_index = False
                continue
            if in_index:
                index_buffer += char
            else:
                buffer += char
        if buffer:
            tokens.append(buffer)
        for token in tokens[:-1]:
            current = current[token]
        current[tokens[-1]] = replacement

    for path, _value in walk(parsed):
        for kind, payload in candidates:
            cloned = deepcopy(parsed)
            set_path(cloned, path, payload)
            output.append(
                {
                    "kind": kind,
                    "field": path,
                    "payload": payload,
                    "message": json.dumps(cloned, separators=(",", ":")),
                }
            )
    return output


def _text_mutations(message: str) -> list[dict[str, Any]]:
    return [
        {
            "kind": "websocket-sqli",
            "field": "message",
            "payload": "' OR '1'='1",
            "message": f"{message}' OR '1'='1",
        },
        {
            "kind": "websocket-nosqli",
            "field": "message",
            "payload": '{"$ne":null}',
            "message": f'{message} {{"$ne":null}}',
        },
        {
            "kind": "websocket-time",
            "field": "message",
            "payload": "sleep(3)",
            "message": f"{message} sleep(3)",
        },
    ]


def _mutations_for_message(message: str) -> list[dict[str, Any]]:
    json_mutations = _json_mutations(message)
    return json_mutations or _text_mutations(message)


def _exchange_message(session: ScanSession, url: str, message: str) -> tuple[str, float]:
    start = time.perf_counter()
    with _WebSocketClient(
        url,
        headers=session.config.ws_headers,
        subprotocols=session.config.ws_subprotocols,
        timeout=session.config.ws_timeout,
        verify_tls=session.config.verify_tls,
    ) as client:
        client.send_text(message)
        response = client.read_message()
    return response, time.perf_counter() - start


def detect_websocket(session: ScanSession) -> list[Finding]:
    if not websocket_enabled(session):
        return []
    url = str(session.config.ws_url or session.config.base_url)
    findings: list[Finding] = []
    baseline_messages = _baseline_messages(session)
    for original in baseline_messages:
        baseline_response, baseline_elapsed = _exchange_message(session, url, original)
        for mutation in _mutations_for_message(original):
            response, elapsed = _exchange_message(session, url, mutation["message"])
            lower = response.lower()
            kind = mutation["kind"]
            signals: list[str] = []
            if mutation["kind"] == "websocket-time":
                if elapsed < baseline_elapsed + max(1.0, baseline_elapsed * 2):
                    continue
                signals.append("timing-outlier")
            else:
                if any(marker in lower for marker in _SQL_MARKERS):
                    kind = "websocket-sqli"
                    signals.append("sql-error-signature")
                elif any(marker in lower for marker in _NOSQL_MARKERS):
                    kind = "websocket-nosqli"
                    signals.append("nosql-error-signature")
                elif response == baseline_response:
                    continue
            findings.append(
                Finding(
                    kind=kind,
                    target=url,
                    details={
                        "protocol": "websocket",
                        "field": mutation["field"],
                        "payload": mutation["payload"],
                        "baseline_elapsed": baseline_elapsed,
                        "elapsed": elapsed,
                        "baseline_response": baseline_response[:200],
                        "response_excerpt": response[:240],
                        "signals": signals,
                        "original_message": original,
                        "mutated_message": mutation["message"],
                    },
                    parameter=str(mutation["field"]),
                    location="websocket",
                )
            )
    if findings:
        session.metadata["websocket"] = {
            "enabled": True,
            "url": url,
            "message_count": len(baseline_messages),
        }
    return findings


__all__ = ["detect_websocket", "websocket_enabled"]
