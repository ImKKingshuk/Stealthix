"""Benchmark fixture builders for local E2E target catalogs."""

from __future__ import annotations

from stealthix.benchmarks import BenchmarkFixtureCatalog


def benchmark_catalog() -> BenchmarkFixtureCatalog:
    return BenchmarkFixtureCatalog.phase1()


def benchmark_base_urls(base_url: str, *, include_live_services: bool = False) -> dict[str, str]:
    catalog = benchmark_catalog()
    return {
        scenario.scenario_id: base_url
        for scenario in catalog.manifest.scenarios
        if include_live_services or not scenario.live_services_required
    }


def benchmark_scan_targets(
    base_url: str, *, include_live_services: bool = False
) -> dict[str, dict[str, object]]:
    catalog = benchmark_catalog()
    return catalog.build_scan_targets(
        benchmark_base_urls(base_url, include_live_services=include_live_services)
    )
