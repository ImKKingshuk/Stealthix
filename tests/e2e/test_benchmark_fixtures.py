from __future__ import annotations

from stealthix.benchmarks import run_benchmark
from stealthix.core.models import Finding, ScanResult
from tests.e2e.fixtures.benchmark_targets import (
    benchmark_base_urls,
    benchmark_catalog,
    benchmark_scan_targets,
)


def test_e2e_benchmark_fixture_builder_maps_local_targets() -> None:
    catalog = benchmark_catalog()
    targets = benchmark_scan_targets("http://localhost:8888")

    assert set(targets) == {
        scenario.scenario_id
        for scenario in catalog.manifest.scenarios
        if not scenario.live_services_required
    }
    assert "websocket.sqli.postgresql.timing" not in targets
    assert targets["sqli.rest.xml.oracle.error"]["body_format"] == "xml"
    assert targets["sqli.rest.multipart.mysql.filemeta"]["body_format"] == "multipart"


def test_e2e_benchmark_runner_with_fake_scan_function() -> None:
    catalog = benchmark_catalog()
    base_urls = benchmark_base_urls("http://localhost:8888")

    def fake_scan(scenario, scan_target):
        return ScanResult(
            target=scan_target["url"],
            findings=[
                Finding(
                    kind=scenario.expected_findings[0].kind,
                    target=scan_target["url"],
                    parameter=(scan_target["target_params"] or [None])[0],
                    location="benchmark",
                    details={"confidence": scenario.expected_findings[0].minimum_confidence},
                )
            ],
            metadata=scan_target["metadata"],
        )

    report = run_benchmark(catalog.manifest, base_urls=base_urls, scan_func=fake_scan)
    summary = report.summary()

    assert summary["completed"] == 7
    assert summary["skipped"] == 1
    assert summary["passed"] == 7
    assert summary["failed"] == 0
