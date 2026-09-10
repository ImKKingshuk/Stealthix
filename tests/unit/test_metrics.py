"""Tests for in-memory metrics collection."""

import threading
import time

from stealthix.core.metrics import (
    Counter,
    Histogram,
    MetricsCollector,
    get_metrics,
    reset_global_metrics,
)


def test_counter_increment():
    """Test that counter increments correctly."""
    counter = Counter()
    assert counter.get_value() == 0
    counter.increment()
    assert counter.get_value() == 1
    counter.increment(5)
    assert counter.get_value() == 6


def test_counter_reset():
    """Test that counter resets correctly."""
    counter = Counter()
    counter.increment(10)
    assert counter.get_value() == 10
    counter.reset()
    assert counter.get_value() == 0


def test_counter_thread_safety():
    """Test that counter is thread-safe."""
    counter = Counter()
    num_threads = 10
    increments_per_thread = 100

    def increment_counter():
        for _ in range(increments_per_thread):
            counter.increment()

    threads = [threading.Thread(target=increment_counter) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert counter.get_value() == num_threads * increments_per_thread


def test_histogram_observe():
    """Test that histogram observes values correctly."""
    histogram = Histogram(buckets=[0.1, 0.5, 1.0, 5.0])
    histogram.observe(0.05)
    histogram.observe(0.3)
    histogram.observe(0.8)
    histogram.observe(2.0)
    histogram.observe(10.0)

    snapshot = histogram.get_snapshot()
    assert snapshot["count"] == 5
    assert snapshot["sum"] == 13.15
    assert snapshot["avg"] == 2.63


def test_histogram_buckets():
    """Test that histogram buckets values correctly."""
    histogram = Histogram(buckets=[0.1, 0.5, 1.0, 5.0])
    histogram.observe(0.05)  # Should go to 0.1 bucket
    histogram.observe(0.3)  # Should go to 0.5 bucket
    histogram.observe(0.8)  # Should go to 1.0 bucket
    histogram.observe(2.0)  # Should go to 5.0 bucket
    histogram.observe(10.0)  # Should go to overflow

    snapshot = histogram.get_snapshot()
    assert snapshot["counts"][0.1] == 1
    assert snapshot["counts"][0.5] == 1
    assert snapshot["counts"][1.0] == 1
    assert snapshot["counts"][5.0] == 1
    assert snapshot["counts"][float("inf")] == 1


def test_histogram_reset():
    """Test that histogram resets correctly."""
    histogram = Histogram(buckets=[0.1, 0.5, 1.0])
    histogram.observe(0.5)
    histogram.observe(1.5)
    assert histogram.get_snapshot()["count"] == 2
    histogram.reset()
    assert histogram.get_snapshot()["count"] == 0
    assert histogram.get_snapshot()["sum"] == 0.0


def test_histogram_thread_safety():
    """Test that histogram is thread-safe."""
    histogram = Histogram(buckets=[0.1, 0.5, 1.0, 5.0])
    num_threads = 10
    observations_per_thread = 100

    def observe_values():
        for i in range(observations_per_thread):
            histogram.observe(i * 0.01)

    threads = [threading.Thread(target=observe_values) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snapshot = histogram.get_snapshot()
    assert snapshot["count"] == num_threads * observations_per_thread


def test_metrics_collector_initialization():
    """Test that MetricsCollector initializes correctly."""
    collector = MetricsCollector()
    snapshot = collector.get_metrics_snapshot()
    assert snapshot["requests"]["total"] == 0
    assert snapshot["findings"]["total"] == 0
    assert snapshot["errors"]["total"] == 0


def test_metrics_collector_increment_request():
    """Test that request metrics increment correctly."""
    collector = MetricsCollector()
    collector.increment_request("http://example.com", "GET", 0.5)
    collector.increment_request("http://example.com", "POST", 1.0)
    collector.increment_request("http://other.com", "GET", 0.3)

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["requests"]["total"] == 3
    assert snapshot["requests"]["by_target"]["http://example.com"] == 2
    assert snapshot["requests"]["by_target"]["http://other.com"] == 1
    assert snapshot["requests"]["by_method"]["GET"] == 2
    assert snapshot["requests"]["by_method"]["POST"] == 1


def test_metrics_collector_increment_finding():
    """Test that finding metrics increment correctly."""
    collector = MetricsCollector()
    collector.increment_finding("Critical", "SQLi")
    collector.increment_finding("High", "SQLi")
    collector.increment_finding("High", "NoSQLi")

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["findings"]["total"] == 3
    assert snapshot["findings"]["by_severity"]["Critical"] == 1
    assert snapshot["findings"]["by_severity"]["High"] == 2
    assert snapshot["findings"]["by_type"]["SQLi"] == 2
    assert snapshot["findings"]["by_type"]["NoSQLi"] == 1


def test_metrics_collector_increment_error():
    """Test that error metrics increment correctly."""
    collector = MetricsCollector()
    collector.increment_error("stealthix.core.engine")
    collector.increment_error("stealthix.core.http")
    collector.increment_error("stealthix.core.engine")

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["errors"]["total"] == 3
    assert snapshot["errors"]["by_module"]["stealthix.core.engine"] == 2
    assert snapshot["errors"]["by_module"]["stealthix.core.http"] == 1


def test_metrics_collector_latency_histogram():
    """Test that latency histogram works correctly."""
    collector = MetricsCollector()
    collector.increment_request("http://example.com", "GET", 0.05)
    collector.increment_request("http://example.com", "GET", 0.3)
    collector.increment_request("http://example.com", "GET", 2.0)

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["latency"]["count"] == 3
    assert snapshot["latency"]["sum"] == 2.35


def test_metrics_collector_scan_duration():
    """Test that scan duration is recorded correctly."""
    collector = MetricsCollector()
    collector.start_scan()
    time.sleep(0.1)
    collector.end_scan()

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["scan"]["duration_seconds"] >= 0.1


def test_metrics_collector_increment_payload():
    """Test that payload count increments correctly."""
    collector = MetricsCollector()
    collector.increment_payload()
    collector.increment_payload()
    collector.increment_payload()

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["scan"]["payloads_tested"] == 3


def test_metrics_collector_reset():
    """Test that metrics reset correctly."""
    collector = MetricsCollector()
    collector.increment_request("http://example.com", "GET", 0.5)
    collector.increment_finding("Critical", "SQLi")
    collector.increment_error("stealthix.core.engine")
    collector.increment_payload()

    collector.reset_metrics()

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["requests"]["total"] == 0
    assert snapshot["findings"]["total"] == 0
    assert snapshot["errors"]["total"] == 0
    assert snapshot["scan"]["payloads_tested"] == 0


def test_metrics_collector_thread_safety():
    """Test that MetricsCollector is thread-safe."""
    collector = MetricsCollector()
    num_threads = 10
    operations_per_thread = 50

    def increment_metrics():
        for _ in range(operations_per_thread):
            collector.increment_request("http://example.com", "GET", 0.5)
            collector.increment_finding("High", "SQLi")
            collector.increment_error("stealthix.core.engine")

    threads = [threading.Thread(target=increment_metrics) for _ in range(num_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    snapshot = collector.get_metrics_snapshot()
    assert snapshot["requests"]["total"] == num_threads * operations_per_thread
    assert snapshot["findings"]["total"] == num_threads * operations_per_thread
    assert snapshot["errors"]["total"] == num_threads * operations_per_thread


def test_get_metrics_singleton():
    """Test that get_metrics returns the same instance."""
    metrics1 = get_metrics()
    metrics2 = get_metrics()
    assert metrics1 is metrics2


def test_reset_global_metrics():
    """Test that reset_global_metrics resets the global instance."""
    reset_global_metrics()  # Reset first to clear state from previous tests

    metrics = get_metrics()
    metrics.increment_request("http://example.com", "GET", 0.5)
    assert metrics.get_metrics_snapshot()["requests"]["total"] == 1

    reset_global_metrics()

    metrics = get_metrics()
    assert metrics.get_metrics_snapshot()["requests"]["total"] == 0


def test_metrics_snapshot_structure():
    """Test that metrics snapshot has correct structure."""
    collector = MetricsCollector()
    snapshot = collector.get_metrics_snapshot()

    assert "requests" in snapshot
    assert "findings" in snapshot
    assert "errors" in snapshot
    assert "latency" in snapshot
    assert "scan" in snapshot

    assert "total" in snapshot["requests"]
    assert "by_target" in snapshot["requests"]
    assert "by_method" in snapshot["requests"]

    assert "total" in snapshot["findings"]
    assert "by_severity" in snapshot["findings"]
    assert "by_type" in snapshot["findings"]

    assert "total" in snapshot["errors"]
    assert "by_module" in snapshot["errors"]

    assert "buckets" in snapshot["latency"]
    assert "counts" in snapshot["latency"]
    assert "sum" in snapshot["latency"]
    assert "count" in snapshot["latency"]
    assert "avg" in snapshot["latency"]

    assert "duration_seconds" in snapshot["scan"]
    assert "payloads_tested" in snapshot["scan"]
