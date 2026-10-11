"""
Endpoint discovery module for reconnaissance.
"""

from __future__ import annotations

import json
import random
import string
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from stealthix.core.http import make_request
from stealthix.core.session import ScanSession
from stealthix.recon.models import DiscoveredEndpoint, ReconConfig, Wordlist


class EndpointDiscovery:
    """Discovers hidden endpoints through probing."""

    def __init__(self, session: ScanSession, config: ReconConfig):
        self.session = session
        self.config = config
        self.wordlists = self._load_wordlists()
        self.soft_404_baseline = None

    def _load_wordlists(self) -> list[Wordlist]:
        """Load built-in and custom wordlists."""
        wordlists: list[Wordlist] = []

        # Load built-in wordlists
        wordlists_path = Path(__file__).parent / "wordlists.json"
        try:
            with open(wordlists_path, encoding="utf-8") as f:
                data = json.load(f)
                for wl in data.get("wordlists", []):
                    wordlists.append(
                        Wordlist(
                            paths=wl["paths"],
                            category=wl["category"],
                            description=wl["description"],
                        )
                    )
        except Exception as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Failed to load built-in wordlists: {exc}"
            )

        # Load custom wordlist if provided
        if self.config.wordlist_path:
            try:
                with open(self.config.wordlist_path, encoding="utf-8") as f:
                    custom_paths = [line.strip() for line in f if line.strip()]
                    wordlists.append(
                        Wordlist(
                            paths=custom_paths,
                            category="custom",
                            description="Custom wordlist",
                        )
                    )
            except Exception as exc:
                self.session.metadata.setdefault("recon_errors", []).append(
                    f"Failed to load custom wordlist: {exc}"
                )

        return wordlists

    def discover(self) -> list[DiscoveredEndpoint]:
        """
        Discover endpoints through concurrent probing.

        Returns list of DiscoveredEndpoint objects.
        """
        discovered: list[DiscoveredEndpoint] = []

        try:
            # Establish soft-404 baseline
            self.soft_404_baseline = self._establish_soft_404_baseline()

            # Collect all paths to probe
            all_paths: list[tuple[str, str]] = []  # (path, category)
            for wordlist in self.wordlists:
                for path in wordlist.paths:
                    all_paths.append((path, wordlist.category))

            # Limit to max_endpoints
            if len(all_paths) > self.config.max_endpoints:
                all_paths = all_paths[: self.config.max_endpoints]

            # Probe each endpoint
            for path, category in all_paths:
                endpoint = self._probe_endpoint(path, category, self.config.use_head_requests)
                if endpoint:
                    discovered.append(endpoint)

        except Exception as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Endpoint discovery failed: {exc}"
            )

        # Deduplicate and return
        return self._deduplicate_endpoints(discovered)

    def _establish_soft_404_baseline(self) -> dict[str, Any]:
        """
        Establish baseline for soft-404 detection.

        Probes random non-existent paths to identify soft-404 patterns.
        """
        baseline = {"sizes": [], "patterns": []}

        try:
            # Generate 3 random non-existent paths
            for _ in range(3):
                random_path = "/" + "".join(
                    random.choices(string.ascii_lowercase + string.digits, k=16)
                )
                url = urljoin(self.session.config.base_url, random_path)

                response = make_request(
                    self.session,
                    method="GET",
                    url=url,
                    data=None,
                )

                # make_request returns (text, elapsed), not a response object
                if response:
                    body = response[0] if isinstance(response, tuple) else str(response)
                    baseline["sizes"].append(len(body))
                    # Store common patterns
                    if "not found" in body.lower():
                        baseline["patterns"].append("not found")
                    if "404" in body:
                        baseline["patterns"].append("404")

        except Exception:
            pass  # Baseline establishment is best-effort

        return baseline

    def _is_soft_404(self, status_code: int, body: str, size: int) -> bool:
        """Detect if response is a soft-404 (200 but actually not found)."""
        if status_code != 200:
            return False

        if not self.soft_404_baseline:
            return False

        # Check if size matches baseline
        baseline_sizes = self.soft_404_baseline.get("sizes", [])
        if baseline_sizes:
            avg_size = sum(baseline_sizes) / len(baseline_sizes)
            # If size is within 10% of baseline average, likely soft-404
            if abs(size - avg_size) / avg_size < 0.1:
                return True

        # Check for common not-found patterns
        body_lower = body.lower()
        return any(pattern in body_lower for pattern in self.soft_404_baseline.get("patterns", []))

    def _probe_endpoint(
        self, path: str, category: str, use_head: bool = True
    ) -> DiscoveredEndpoint | None:
        """Probe a single endpoint and return result if valid."""
        url = urljoin(self.session.config.base_url, path)

        try:
            start_time = time.time()

            # Try HEAD first
            method = "HEAD" if use_head else "GET"
            response = make_request(
                self.session,
                method=method,
                url=url,
                data=None,
            )

            # If HEAD was rejected (e.g. 405 Method Not Allowed or 501 Not Implemented), retry with GET
            if use_head and response and method == "HEAD":
                head_entry = next(
                    (
                        entry
                        for entry in reversed(self.session.history.to_list())
                        if entry.get("url") == url and entry.get("method") == "HEAD"
                    ),
                    {},
                )
                head_meta = (
                    head_entry.get("metadata")
                    if isinstance(head_entry.get("metadata"), dict)
                    else {}
                )
                head_status = (
                    head_meta.get("status_code")
                    if isinstance(head_meta, dict)
                    else head_entry.get("status")
                )
                try:
                    head_code = int(head_status) if head_status is not None else 200
                except (TypeError, ValueError):
                    head_code = 200

                if head_code in {405, 501}:
                    response = make_request(
                        self.session,
                        method="GET",
                        url=url,
                        data=None,
                    )
                    method = "GET"

            elapsed = time.time() - start_time

            if not response:
                return None

            body = response[0] if isinstance(response, tuple) else str(response)
            history_entry = next(
                (
                    entry
                    for entry in reversed(self.session.history.to_list())
                    if entry.get("url") == url and entry.get("method") == method
                ),
                {},
            )
            metadata = (
                history_entry.get("metadata")
                if isinstance(history_entry.get("metadata"), dict)
                else {}
            )
            response_headers = (
                dict(metadata.get("headers") or {}) if isinstance(metadata, dict) else {}
            )
            status_value = (
                metadata.get("status_code")
                if isinstance(metadata, dict)
                else history_entry.get("status")
            )
            try:
                status_code = int(status_value) if status_value is not None else 200
            except (TypeError, ValueError):
                status_code = 200
            size = len(body)

            # Check if valid discovery
            if not self._is_valid_discovery(status_code, body, size):
                return None

            # Check for honeypot
            is_honeypot = self._detect_honeypot(url, body, response_headers)
            confidence = 0.9

            return DiscoveredEndpoint(
                url=url,
                status_code=status_code,
                response_size=size,
                response_time=elapsed,
                category=category,
                confidence=confidence,
                evidence={
                    "method": method,
                    "requires_auth": status_code in (401, 403),
                    "honeypot": is_honeypot,
                },
            )

        except Exception:
            return None

    def _is_valid_discovery(self, status_code: int, body: str, size: int) -> bool:
        """Determine if response indicates a valid endpoint."""
        # Valid status codes
        if status_code in (200, 401, 403):
            # Check for soft-404
            if status_code == 200 and self._is_soft_404(status_code, body, size):
                return False
            return True

        # Exclude not found
        if status_code in (404, 410):
            return False

        return False

    def _detect_honeypot(self, url: str, body: str, headers: dict[str, str]) -> bool:
        """Detect honeypot patterns in response."""
        # Check for suspicious headers
        honeypot_headers = ["X-Honeypot", "X-Trap", "X-Canary"]
        for header in honeypot_headers:
            if header.lower() in [h.lower() for h in headers.keys()]:
                return True

        # Check for trap content
        body_lower = body.lower()
        trap_patterns = ["honeypot", "trap", "canary", "decoy"]
        return any(pattern in body_lower for pattern in trap_patterns)

    def _deduplicate_endpoints(
        self, endpoints: list[DiscoveredEndpoint]
    ) -> list[DiscoveredEndpoint]:
        """Remove duplicate endpoints based on normalized URLs."""
        seen: set[str] = set()
        deduplicated: list[DiscoveredEndpoint] = []

        for endpoint in endpoints:
            # Normalize URL
            parsed = urlparse(endpoint.url)
            normalized = f"{parsed.scheme}://{parsed.netloc}{parsed.path.rstrip('/')}"

            if normalized not in seen:
                seen.add(normalized)
                deduplicated.append(endpoint)

        return deduplicated
