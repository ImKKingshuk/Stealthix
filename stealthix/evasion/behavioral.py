"""Behavioral analysis evasion to mimic legitimate traffic patterns.

This module provides timing analysis, header normalization, and session
simulation to evade behavioral analysis by WAFs.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

# Realistic User-Agent strings for common browsers
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
]

# Common Accept-Language headers
_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en-US;q=0.9,en;q=0.8",
    "en-US,en;q=0.5",
    "en;q=0.9",
]


@dataclass
class TimingProfile:
    """Profile of realistic timing patterns."""

    min_interval_ms: float = 100.0
    max_interval_ms: float = 5000.0
    mean_interval_ms: float = 500.0
    jitter_ms: float = 200.0


class TimingAnalyzer:
    """Analyze and mimic legitimate timing patterns.

    Generates human-like request intervals and adds realistic
    jitter to evade timing-based detection.
    """

    def __init__(self) -> None:
        self._profile = TimingProfile()
        self._last_request_time: float = 0.0
        self._request_count: int = 0

    def analyze_baseline(self, intervals: list[float]) -> TimingProfile:
        """Analyze baseline timing patterns from legitimate traffic."""
        if not intervals:
            return self._profile

        self._profile.min_interval_ms = min(intervals)
        self._profile.max_interval_ms = max(intervals)
        self._profile.mean_interval_ms = sum(intervals) / len(intervals)

        # Calculate jitter as standard deviation
        if len(intervals) > 1:
            variance = sum((x - self._profile.mean_interval_ms) ** 2 for x in intervals) / len(
                intervals
            )
            self._profile.jitter_ms = variance**0.5

        return self._profile

    def get_next_interval(self) -> float:
        """Get next request interval with realistic jitter."""
        base_interval = random.gauss(self._profile.mean_interval_ms, self._profile.jitter_ms)

        # Clamp to min/max bounds
        base_interval = max(
            self._profile.min_interval_ms, min(base_interval, self._profile.max_interval_ms)
        )

        # Add human-like randomness (occasional longer pauses)
        if random.random() < 0.1:  # 10% chance of longer pause
            base_interval *= random.uniform(1.5, 3.0)

        return base_interval / 1000.0  # Convert to seconds

    def wait_for_next_request(self) -> None:
        """Wait for appropriate interval before next request."""
        interval = self.get_next_interval()
        time.sleep(interval)
        self._last_request_time = time.time()
        self._request_count += 1

    def simulate_human_browsing(self, request_count: int) -> list[float]:
        """Simulate human browsing pattern with realistic intervals."""
        intervals = []
        for _ in range(request_count):
            interval = self.get_next_interval()
            intervals.append(interval)
            time.sleep(interval)

        return intervals


class HeaderNormalizer:
    """Normalize headers to match legitimate traffic patterns.

    Rotates User-Agents, normalizes Accept-Language, and handles
    other headers to appear as legitimate browser traffic.
    """

    def __init__(self) -> None:
        self._user_agents = list(_USER_AGENTS)
        self._accept_languages = list(_ACCEPT_LANGUAGES)
        self._current_user_agent_index = 0
        self._current_accept_language_index = 0

    def get_user_agent(self) -> str:
        """Get a realistic User-Agent string."""
        ua = self._user_agents[self._current_user_agent_index]
        self._current_user_agent_index = (self._current_user_agent_index + 1) % len(
            self._user_agents
        )
        return ua

    def get_accept_language(self) -> str:
        """Get a realistic Accept-Language header."""
        lang = self._accept_languages[self._current_accept_language_index]
        self._current_accept_language_index = (self._current_accept_language_index + 1) % len(
            self._accept_languages
        )
        return lang

    def normalize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Normalize headers to match legitimate traffic patterns."""
        normalized = dict(headers)

        # Set User-Agent if not present or looks suspicious
        if "user-agent" not in normalized or self._is_suspicious_user_agent(
            normalized.get("user-agent", "")
        ):
            normalized["user-agent"] = self.get_user_agent()

        # Set Accept-Language if not present
        if "accept-language" not in normalized:
            normalized["accept-language"] = self.get_accept_language()

        # Add common headers if missing
        if "accept" not in normalized:
            normalized["accept"] = (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
            )

        if "accept-encoding" not in normalized:
            normalized["accept-encoding"] = "gzip, deflate, br"

        if "connection" not in normalized:
            normalized["connection"] = "keep-alive"

        if "upgrade-insecure-requests" not in normalized:
            normalized["upgrade-insecure-requests"] = "1"

        return normalized

    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Check if User-Agent looks suspicious."""
        suspicious_indicators = [
            "python",
            "curl",
            "wget",
            "bot",
            "crawler",
            "spider",
            "scanner",
            "sqlmap",
        ]
        user_agent_lower = user_agent.lower()
        return any(indicator in user_agent_lower for indicator in suspicious_indicators)

    def rotate_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Rotate header values to avoid pattern detection."""
        rotated = dict(headers)

        # Rotate User-Agent
        if "user-agent" in rotated:
            rotated["user-agent"] = self.get_user_agent()

        # Rotate Accept-Language
        if "accept-language" in rotated:
            rotated["accept-language"] = self.get_accept_language()

        return rotated


class SessionSimulator:
    """Simulate realistic browsing sessions.

    Generates sequential request patterns, navigation paths,
    and handles cookies to mimic real user behavior.
    """

    def __init__(self) -> None:
        self._session_cookies: dict[str, str] = {}
        self._navigation_history: list[str] = []
        self._current_path: str = "/"
        self._referrer: str | None = None

    def start_session(self, initial_url: str) -> None:
        """Start a new browsing session."""
        self._navigation_history = [initial_url]
        self._current_path = self._extract_path(initial_url)
        self._referrer = None

    def _extract_path(self, url: str) -> str:
        """Extract path from URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.path or "/"

    def navigate_to(self, url: str) -> dict[str, Any]:
        """Navigate to a new URL in the session."""
        path = self._extract_path(url)
        headers = {}

        # Set Referer header
        if self._referrer:
            headers["referer"] = self._referrer

        # Update navigation history
        self._navigation_history.append(url)
        self._referrer = url
        self._current_path = path

        return headers

    def simulate_navigation_sequence(self, urls: list[str]) -> list[dict[str, Any]]:
        """Simulate a sequence of navigation requests."""
        headers_list = []

        for i, url in enumerate(urls):
            if i == 0:
                self.start_session(url)
            else:
                headers = self.navigate_to(url)
                headers_list.append(headers)

        return headers_list

    def get_cookies(self) -> dict[str, str]:
        """Get current session cookies."""
        return dict(self._session_cookies)

    def set_cookie(self, name: str, value: str) -> None:
        """Set a session cookie."""
        self._session_cookies[name] = value

    def get_cookie_headers(self) -> dict[str, str]:
        """Get Cookie header for requests."""
        if not self._session_cookies:
            return {}

        cookie_string = "; ".join(f"{k}={v}" for k, v in self._session_cookies.items())
        return {"cookie": cookie_string}


class BehavioralProfile:
    """Profile legitimate traffic patterns and generate realistic requests.

    Learns from baseline traffic and generates realistic request
    sequences to evade behavioral anomaly detection.
    """

    def __init__(self) -> None:
        self._baseline_requests: list[dict[str, Any]] = []
        self._timing_analyzer = TimingAnalyzer()
        self._header_normalizer = HeaderNormalizer()
        self._session_simulator = SessionSimulator()

    def learn_from_baseline(self, requests: list[dict[str, Any]]) -> None:
        """Learn patterns from baseline legitimate traffic."""
        self._baseline_requests = requests.copy()

        # Extract timing patterns
        intervals = []
        for i in range(1, len(requests)):
            prev_time = requests[i - 1].get("timestamp", 0)
            curr_time = requests[i].get("timestamp", 0)
            if curr_time > prev_time:
                intervals.append((curr_time - prev_time) * 1000)  # Convert to ms

        if intervals:
            self._timing_analyzer.analyze_baseline(intervals)

    def generate_realistic_request(
        self, url: str, method: str = "GET", headers: dict[str, str] | None = None
    ) -> dict[str, Any]:
        """Generate a realistic request based on learned patterns."""
        if headers is None:
            headers = {}

        # Normalize headers
        normalized_headers = self._header_normalizer.normalize_headers(headers)

        # Add session cookies if available
        cookie_headers = self._session_simulator.get_cookie_headers()
        normalized_headers.update(cookie_headers)

        # Get appropriate timing
        interval = self._timing_analyzer.get_next_interval()

        return {
            "url": url,
            "method": method,
            "headers": normalized_headers,
            "timing_interval": interval,
        }

    def generate_realistic_sequence(
        self, base_url: str, path_count: int = 5
    ) -> list[dict[str, Any]]:
        """Generate a sequence of realistic requests."""
        # Generate realistic paths
        common_paths = [
            "/",
            "/index.html",
            "/login",
            "/dashboard",
            "/api/data",
            "/search",
            "/profile",
            "/settings",
        ]

        requests = []
        for i in range(min(path_count, len(common_paths))):
            url = base_url + common_paths[i]
            request = self.generate_realistic_request(url)
            requests.append(request)

        return requests

    def detect_anomaly(self, request: dict[str, Any]) -> tuple[bool, float]:
        """Detect if request deviates from learned patterns."""
        anomaly_score = 0.0

        # Check header anomalies
        headers = request.get("headers", {})
        if "user-agent" in headers:
            ua = headers["user-agent"]
            if self._header_normalizer._is_suspicious_user_agent(ua):
                anomaly_score += 0.4

        # Check timing anomalies
        timing = request.get("timing_interval", 0)
        if timing < 0.01:  # Less than 10ms is suspicious
            anomaly_score += 0.3
        elif timing > 10.0:  # More than 10s is suspicious
            anomaly_score += 0.2

        # Check for missing common headers
        common_headers = ["user-agent", "accept", "accept-language"]
        missing_count = sum(1 for h in common_headers if h not in headers)
        anomaly_score += missing_count * 0.1

        is_anomaly = anomaly_score >= 0.5
        return is_anomaly, anomaly_score


def apply_timing_evasion(min_interval_ms: float = 100.0, max_interval_ms: float = 5000.0) -> float:
    """Apply timing evasion with realistic intervals."""
    analyzer = TimingAnalyzer()
    analyzer._profile.min_interval_ms = min_interval_ms
    analyzer._profile.max_interval_ms = max_interval_ms
    analyzer._profile.mean_interval_ms = (min_interval_ms + max_interval_ms) / 2
    return analyzer.get_next_interval()


def normalize_request_headers(headers: dict[str, str]) -> dict[str, str]:
    """Normalize request headers to match legitimate traffic."""
    normalizer = HeaderNormalizer()
    return normalizer.normalize_headers(headers)


def simulate_browsing_session(urls: list[str]) -> list[dict[str, Any]]:
    """Simulate a browsing session with realistic patterns."""
    simulator = SessionSimulator()
    return simulator.simulate_navigation_sequence(urls)
