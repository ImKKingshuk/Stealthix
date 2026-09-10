"""Mock HTTP server for E2E testing."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any


class MockHandler(BaseHTTPRequestHandler):
    """Handler for mock HTTP requests."""

    def do_GET(self):
        """Handle GET requests."""
        if self.path == "/vulnerable":
            self._send_json_response({"id": "1", "name": "test"})
        elif self.path == "/api/data":
            self._send_json_response({"data": [{"id": 1, "value": "test"}]})
        elif self.path == "/health":
            self._send_json_response({"status": "ok"})
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests."""
        if self.path == "/login":
            self._send_json_response({"token": "mock_token_123"})
        elif self.path == "/api/search":
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            try:
                data = json.loads(body)
                self._send_json_response({"results": [{"id": 1, "query": data.get("q", "")}]})
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

    def _send_json_response(self, data: dict[str, Any]) -> None:
        """Send JSON response."""
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def log_message(self, format: str, *args: Any) -> None:
        """Suppress log messages."""
        pass


class MockServer:
    """Mock HTTP server for testing."""

    def __init__(self, port: int = 8888):
        self.port = port
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the mock server."""
        self.server = HTTPServer(("localhost", self.port), MockHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def stop(self) -> None:
        """Stop the mock server."""
        if self.server:
            self.server.shutdown()

    @property
    def url(self) -> str:
        """Get the base URL of the mock server."""
        return f"http://localhost:{self.port}"
