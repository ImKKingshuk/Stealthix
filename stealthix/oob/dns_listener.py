from __future__ import annotations

import atexit
import socketserver
import threading
import time
from dataclasses import dataclass


def _parse_qname(packet: bytes) -> str | None:
    if len(packet) < 12:
        return None
    idx = 12
    labels: list[str] = []
    while idx < len(packet):
        length = packet[idx]
        idx += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        if idx + length > len(packet):
            return None
        label = packet[idx : idx + length].decode("ascii", errors="ignore")
        labels.append(label)
        idx += length
        if len(labels) > 128:
            return None
    if not labels:
        return None
    return ".".join(labels).lower()


def _question_section(packet: bytes) -> bytes | None:
    if len(packet) < 12:
        return None
    idx = 12
    while idx < len(packet):
        length = packet[idx]
        idx += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        idx += length
    if idx + 4 > len(packet):
        return None
    return packet[12 : idx + 4]


def _nxdomain_response(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    q = _question_section(query)
    if q is None:
        return None
    txn_id = query[0:2]
    flags = b"\x81\x83"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    return txn_id + flags + counts + q


class _Handler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        data = self.request[0]
        sock = self.request[1]
        qname = _parse_qname(data)
        if qname:
            getattr(self.server, "_record_query", lambda x: None)(qname)
        resp = _nxdomain_response(data)
        if resp:
            sock.sendto(resp, self.client_address)


@dataclass
class DnsCallbackListener:
    host: str = "127.0.0.1"
    port: int = 53535

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._seen: set[str] = set()
        self._events: list[dict[str, float | str]] = []
        self._server: socketserver.ThreadingUDPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def bound_port(self) -> int:
        if not self._server:
            return self.port
        return int(self._server.server_address[1])

    def _record_query(self, qname: str) -> None:
        with self._lock:
            self._seen.add(qname)
            self._events.append({"qname": qname, "timestamp": time.time()})

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()
            self._events.clear()

    def seen_queries(self, suffix: str | None = None) -> list[str]:
        suffix_lower = (suffix or "").strip().lower()
        with self._lock:
            items = sorted(self._seen)
        if not suffix_lower:
            return items
        return [item for item in items if item.endswith(suffix_lower)]

    def query_log(
        self, suffix: str | None = None, token: str | None = None
    ) -> list[dict[str, float | str]]:
        suffix_lower = (suffix or "").strip().lower()
        token_lower = (token or "").strip().lower()
        with self._lock:
            events = [dict(item) for item in self._events]
        if suffix_lower:
            events = [
                item for item in events if str(item.get("qname") or "").endswith(suffix_lower)
            ]
        if token_lower:
            events = [item for item in events if token_lower in str(item.get("qname") or "")]
        return events

    def start(self) -> None:
        if self._server:
            return
        server = socketserver.ThreadingUDPServer((self.host, self.port), _Handler)
        server.daemon_threads = True
        setattr(server, "_record_query", self._record_query)  # type: ignore[attr-defined]  # noqa: B010
        self._server = server
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread = thread
        thread.start()

    def stop(self) -> None:
        if not self._server:
            return
        server = self._server
        self._server = None
        try:
            server.shutdown()
        finally:
            server.server_close()

    def wait_for_token(self, token: str, timeout: float = 5.0) -> bool:
        token = (token or "").lower()
        if not token:
            return False
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            with self._lock:
                if any(token in q for q in self._seen):
                    return True
            time.sleep(0.05)
        return False

    def wait_for_tokens(self, tokens: list[str], timeout: float = 5.0) -> dict[str, bool]:
        normalized = [str(token or "").lower() for token in tokens if str(token or "").strip()]
        results = dict.fromkeys(normalized, False)
        if not normalized:
            return results
        start = time.monotonic()
        while time.monotonic() - start < timeout:
            with self._lock:
                for token in normalized:
                    if not results[token] and any(token in q for q in self._seen):
                        results[token] = True
            if all(results.values()):
                return results
            time.sleep(0.05)
        return results


_GLOBAL: DnsCallbackListener | None = None


def get_global_listener(host: str = "127.0.0.1", port: int = 53535) -> DnsCallbackListener:
    global _GLOBAL
    if _GLOBAL is None:
        listener = DnsCallbackListener(host=host, port=port)
        listener.start()
        _GLOBAL = listener
        atexit.register(listener.stop)
    return _GLOBAL
