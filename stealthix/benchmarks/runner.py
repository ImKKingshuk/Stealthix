"""Benchmark runner API for Stealthix and optional external tool accounting."""

from __future__ import annotations

import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from stealthix.benchmarks.catalog import BenchmarkFixtureCatalog
from stealthix.benchmarks.models import (
    CONFIDENCE_RANK,
    BenchmarkManifest,
    BenchmarkScenario,
)
from stealthix.core.engine import Engine
from stealthix.core.models import Finding, ScanResult
from stealthix.core.session import ScanSession, SessionConfig

ScanFunction = Callable[[BenchmarkScenario, dict[str, Any]], ScanResult]


@dataclass(frozen=True)
class ExternalToolSpec:
    """Optional competitor tool metadata.

    The Phase 1 harness records availability only. It intentionally does not
    execute external scanners during tests.
    """

    name: str
    executable: str
    args: tuple[str, ...] = ()

    def to_status(self) -> ExternalToolStatus:
        resolved = shutil.which(self.executable)
        return ExternalToolStatus(
            name=self.name,
            executable=self.executable,
            installed=resolved is not None,
            resolved_path=resolved,
            args=list(self.args),
        )


@dataclass(frozen=True)
class ExternalToolStatus:
    name: str
    executable: str
    installed: bool
    resolved_path: str | None = None
    args: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "executable": self.executable,
            "installed": self.installed,
            "resolved_path": self.resolved_path,
            "args": list(self.args),
        }


@dataclass(frozen=True)
class FindingRecord:
    kind: str
    target: str
    parameter: str | None
    location: str | None
    confidence: str
    confidence_score: float | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "parameter": self.parameter,
            "location": self.location,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
        }


@dataclass(frozen=True)
class BenchmarkComparisonRecord:
    scenario_id: str
    tool_name: str
    status: str
    target_url: str | None
    expected_kinds: list[str]
    observed_kinds: list[str] = field(default_factory=list)
    matched_expected: list[str] = field(default_factory=list)
    missed_expected: list[str] = field(default_factory=list)
    unexpected_kinds: list[str] = field(default_factory=list)
    confidence_failures: list[dict[str, str]] = field(default_factory=list)
    findings: list[FindingRecord] = field(default_factory=list)
    passed: bool = False
    duration_seconds: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "tool_name": self.tool_name,
            "status": self.status,
            "target_url": self.target_url,
            "expected_kinds": list(self.expected_kinds),
            "observed_kinds": list(self.observed_kinds),
            "matched_expected": list(self.matched_expected),
            "missed_expected": list(self.missed_expected),
            "unexpected_kinds": list(self.unexpected_kinds),
            "confidence_failures": [dict(item) for item in self.confidence_failures],
            "findings": [finding.to_dict() for finding in self.findings],
            "passed": self.passed,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
        }


@dataclass(frozen=True)
class BenchmarkRunReport:
    manifest_id: str
    manifest_version: str
    coverage: dict[str, Any]
    records: list[BenchmarkComparisonRecord]
    external_tools: list[ExternalToolStatus] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "manifest_version": self.manifest_version,
            "coverage": dict(self.coverage),
            "external_tools": [tool.to_dict() for tool in self.external_tools],
            "records": [record.to_dict() for record in self.records],
            "summary": self.summary(),
        }

    def summary(self) -> dict[str, Any]:
        executed = [record for record in self.records if record.status == "completed"]
        return {
            "total_records": len(self.records),
            "completed": len(executed),
            "skipped": sum(1 for record in self.records if record.status == "skipped"),
            "errors": sum(1 for record in self.records if record.status == "error"),
            "passed": sum(1 for record in executed if record.passed),
            "failed": sum(1 for record in executed if not record.passed),
        }


def run_benchmark(
    manifest: BenchmarkManifest,
    *,
    base_urls: dict[str, str] | None = None,
    scan_func: ScanFunction | None = None,
    external_tools: tuple[ExternalToolSpec, ...] = (),
    tool_name: str = "stealthix",
) -> BenchmarkRunReport:
    """Execute benchmark scenarios with provided local/mock target URLs.

    Scenarios without a configured URL are reported as skipped. Tests can pass a
    fake ``scan_func`` to validate comparison behavior without live services.
    """

    catalog = BenchmarkFixtureCatalog(manifest)
    urls = dict(base_urls or {})
    scanner = scan_func or default_stealthix_scan
    records: list[BenchmarkComparisonRecord] = []

    for scenario in manifest.scenarios:
        expected_kinds = [item.kind for item in scenario.expected_findings]
        base_url = urls.get(scenario.scenario_id)
        if not base_url:
            records.append(
                BenchmarkComparisonRecord(
                    scenario_id=scenario.scenario_id,
                    tool_name=tool_name,
                    status="skipped",
                    target_url=None,
                    expected_kinds=expected_kinds,
                    missed_expected=expected_kinds,
                    error="No target URL configured for scenario.",
                )
            )
            continue

        scan_target = catalog.build_scan_target(scenario.scenario_id, base_url)
        started = time.perf_counter()
        try:
            result = scanner(scenario, scan_target)
        except Exception as exc:
            records.append(
                BenchmarkComparisonRecord(
                    scenario_id=scenario.scenario_id,
                    tool_name=tool_name,
                    status="error",
                    target_url=scan_target["url"],
                    expected_kinds=expected_kinds,
                    missed_expected=expected_kinds,
                    duration_seconds=time.perf_counter() - started,
                    error=f"{type(exc).__name__}: {exc}",
                )
            )
            continue

        records.append(
            compare_scan_result(
                scenario,
                result,
                tool_name=tool_name,
                target_url=scan_target["url"],
                duration_seconds=time.perf_counter() - started,
            )
        )

    return BenchmarkRunReport(
        manifest_id=manifest.manifest_id,
        manifest_version=manifest.version,
        coverage=manifest.coverage_summary().to_dict(),
        records=records,
        external_tools=[tool.to_status() for tool in external_tools],
    )


def compare_scan_result(
    scenario: BenchmarkScenario,
    result: ScanResult,
    *,
    tool_name: str,
    target_url: str | None,
    duration_seconds: float = 0.0,
) -> BenchmarkComparisonRecord:
    finding_records = [_finding_record(item) for item in result.findings]
    observed_kinds = sorted({item.kind for item in finding_records})
    expected_kinds = [item.kind for item in scenario.expected_findings]
    expected_set = set(expected_kinds)
    observed_set = set(observed_kinds)
    matched = sorted(expected_set & observed_set)
    missed = [kind for kind in expected_kinds if kind not in observed_set]
    unexpected = sorted(observed_set - expected_set)
    confidence_failures = _confidence_failures(scenario, finding_records)
    passed = not missed and not confidence_failures

    return BenchmarkComparisonRecord(
        scenario_id=scenario.scenario_id,
        tool_name=tool_name,
        status="completed",
        target_url=target_url,
        expected_kinds=expected_kinds,
        observed_kinds=observed_kinds,
        matched_expected=matched,
        missed_expected=missed,
        unexpected_kinds=unexpected,
        confidence_failures=confidence_failures,
        findings=finding_records,
        passed=passed,
        duration_seconds=duration_seconds,
    )


def default_stealthix_scan(scenario: BenchmarkScenario, scan_target: dict[str, Any]) -> ScanResult:
    """Run a single Stealthix scan from a benchmark scan-target dictionary."""

    config = SessionConfig(
        base_url=str(scan_target["url"]),
        method=str(scan_target.get("method") or "GET"),
        body_format=str(scan_target.get("body_format") or "form"),
        data=scan_target.get("data") if isinstance(scan_target.get("data"), dict) else None,
        headers=dict(scan_target.get("headers") or {}),
        target_params=[str(item) for item in scan_target.get("target_params") or []] or None,
        dbms=scenario.dbms_family,
        auth_type=scan_target.get("auth_type"),
        auth_token=scan_target.get("auth_token"),
        ws_url=scan_target.get("ws_url"),
        ws_messages=list(scan_target.get("ws_messages") or []) or None,
    )
    session = ScanSession(config, metadata=dict(scan_target.get("metadata") or {}))
    return Engine(session).detect()


def _finding_record(finding: Finding) -> FindingRecord:
    details = finding.details if isinstance(finding.details, dict) else {}
    confidence_score = details.get("confidence_score")
    return FindingRecord(
        kind=str(finding.kind),
        target=str(finding.target),
        parameter=finding.parameter,
        location=finding.location,
        confidence=_confidence_label(details),
        confidence_score=float(confidence_score)
        if isinstance(confidence_score, int | float)
        else None,
    )


def _confidence_label(details: dict[str, Any]) -> str:
    confidence = str(details.get("confidence") or "").strip().lower()
    if confidence in CONFIDENCE_RANK:
        return confidence
    score = details.get("confidence_score")
    if isinstance(score, int | float):
        if score >= 0.95:
            return "confirmed"
        if score >= 0.75:
            return "high"
        if score >= 0.45:
            return "medium"
        return "low"
    return "unscored"


def _confidence_failures(
    scenario: BenchmarkScenario, finding_records: list[FindingRecord]
) -> list[dict[str, str]]:
    failures: list[dict[str, str]] = []
    by_kind = {record.kind: record for record in finding_records}
    for expected in scenario.expected_findings:
        record = by_kind.get(expected.kind)
        if record is None:
            continue
        required_rank = CONFIDENCE_RANK[expected.minimum_confidence]
        observed_rank = CONFIDENCE_RANK.get(record.confidence, 0)
        if observed_rank < required_rank:
            failures.append(
                {
                    "kind": expected.kind,
                    "required": expected.minimum_confidence,
                    "observed": record.confidence,
                }
            )
    return failures
