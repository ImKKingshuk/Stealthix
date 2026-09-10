"""In-memory metrics collection for Stealthix scan monitoring."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Histogram:
    """Thread-safe histogram for tracking value distributions."""

    buckets: list[float]
    counts: dict[float, int] = field(default_factory=dict)
    sum: float = 0.0
    count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def observe(self, value: float) -> None:
        """Record a value in the histogram."""
        with self.lock:
            self.sum += value
            self.count += 1

            # Find the appropriate bucket
            for bucket in self.buckets:
                if value <= bucket:
                    self.counts[bucket] = self.counts.get(bucket, 0) + 1
                    break
            else:
                # Value exceeds all buckets, count in overflow
                self.counts[float("inf")] = self.counts.get(float("inf"), 0) + 1

    def get_snapshot(self) -> dict[str, Any]:
        """Get a snapshot of histogram data."""
        with self.lock:
            return {
                "buckets": self.buckets,
                "counts": dict(self.counts),
                "sum": self.sum,
                "count": self.count,
                "avg": self.sum / self.count if self.count > 0 else 0.0,
            }

    def reset(self) -> None:
        """Reset the histogram."""
        with self.lock:
            self.counts.clear()
            self.sum = 0.0
            self.count = 0


@dataclass
class Counter:
    """Thread-safe counter."""

    value: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def increment(self, amount: int = 1) -> None:
        """Increment the counter."""
        with self.lock:
            self.value += amount

    def get_value(self) -> int:
        """Get the current value."""
        with self.lock:
            return self.value

    def reset(self) -> None:
        """Reset the counter."""
        with self.lock:
            self.value = 0


class MetricsCollector:
    """Thread-safe metrics collector for Stealthix scans."""

    def __init__(self) -> None:
        """Initialize the metrics collector."""
        self._lock = threading.Lock()

        # Request metrics
        self._request_count_total = Counter()
        self._request_count_by_target: dict[str, Counter] = defaultdict(Counter)
        self._request_count_by_method: dict[str, Counter] = defaultdict(Counter)

        # Finding metrics
        self._finding_count_total = Counter()
        self._finding_count_by_severity: dict[str, Counter] = defaultdict(Counter)
        self._finding_count_by_type: dict[str, Counter] = defaultdict(Counter)

        # Error metrics
        self._error_count_total = Counter()
        self._error_count_by_module: dict[str, Counter] = defaultdict(Counter)

        # Latency histogram (buckets in seconds)
        self._latency_histogram = Histogram(buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0, 300.0])

        # Scan metrics
        self._scan_duration_seconds = 0.0
        self._scan_start_time: float | None = None
        self._payload_count_total = Counter()

    def increment_request(self, target: str, method: str, latency: float) -> None:
        """Record an HTTP request.

        Args:
            target: Target URL
            method: HTTP method (GET, POST, etc.)
            latency: Request latency in seconds
        """
        self._request_count_total.increment()
        self._request_count_by_target[target].increment()
        self._request_count_by_method[method].increment()
        self._latency_histogram.observe(latency)

    def increment_finding(self, severity: str, finding_type: str) -> None:
        """Record a vulnerability finding.

        Args:
            severity: Finding severity (Critical, High, Medium, Low)
            finding_type: Type of finding (SQLi, NoSQLi, IDOR, etc.)
        """
        self._finding_count_total.increment()
        self._finding_count_by_severity[severity].increment()
        self._finding_count_by_type[finding_type].increment()

    def increment_error(self, module: str) -> None:
        """Record an error.

        Args:
            module: Module where error occurred
        """
        self._error_count_total.increment()
        self._error_count_by_module[module].increment()

    def increment_payload(self) -> None:
        """Record a payload tested."""
        self._payload_count_total.increment()

    def start_scan(self) -> None:
        """Mark the start of a scan."""
        with self._lock:
            self._scan_start_time = time.time()

    def end_scan(self) -> None:
        """Mark the end of a scan and record duration."""
        with self._lock:
            if self._scan_start_time is not None:
                self._scan_duration_seconds = time.time() - self._scan_start_time
                self._scan_start_time = None

    def get_metrics_snapshot(self) -> dict[str, Any]:
        """Get a snapshot of all metrics.

        Returns:
            Dictionary containing all current metrics
        """
        with self._lock:
            return {
                "requests": {
                    "total": self._request_count_total.get_value(),
                    "by_target": {
                        k: v.get_value() for k, v in self._request_count_by_target.items()
                    },
                    "by_method": {
                        k: v.get_value() for k, v in self._request_count_by_method.items()
                    },
                },
                "findings": {
                    "total": self._finding_count_total.get_value(),
                    "by_severity": {
                        k: v.get_value() for k, v in self._finding_count_by_severity.items()
                    },
                    "by_type": {k: v.get_value() for k, v in self._finding_count_by_type.items()},
                },
                "errors": {
                    "total": self._error_count_total.get_value(),
                    "by_module": {k: v.get_value() for k, v in self._error_count_by_module.items()},
                },
                "latency": self._latency_histogram.get_snapshot(),
                "scan": {
                    "duration_seconds": self._scan_duration_seconds,
                    "payloads_tested": self._payload_count_total.get_value(),
                },
            }

    def reset_metrics(self) -> None:
        """Reset all metrics to zero."""
        with self._lock:
            self._request_count_total.reset()
            self._request_count_by_target.clear()
            self._request_count_by_method.clear()
            self._finding_count_total.reset()
            self._finding_count_by_severity.clear()
            self._finding_count_by_type.clear()
            self._error_count_total.reset()
            self._error_count_by_module.clear()
            self._latency_histogram.reset()
            self._scan_duration_seconds = 0.0
            self._scan_start_time = None
            self._payload_count_total.reset()


# Global metrics collector instance
_global_metrics: MetricsCollector | None = None
_global_metrics_lock = threading.Lock()


def get_metrics() -> MetricsCollector:
    """Get the global metrics collector instance.

    Returns:
        The global MetricsCollector instance
    """
    global _global_metrics
    if _global_metrics is None:
        with _global_metrics_lock:
            if _global_metrics is None:
                _global_metrics = MetricsCollector()
    return _global_metrics


def reset_global_metrics() -> None:
    """Reset the global metrics collector."""
    global _global_metrics
    with _global_metrics_lock:
        if _global_metrics is not None:
            _global_metrics.reset_metrics()
