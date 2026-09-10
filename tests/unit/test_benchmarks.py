from __future__ import annotations

from stealthix.benchmarks import (
    BenchmarkFixtureCatalog,
    BenchmarkManifest,
    ExternalToolSpec,
    phase1_manifest,
    run_benchmark,
)
from stealthix.core.models import Finding, ScanResult


def test_phase1_manifest_serializes_with_expected_coverage() -> None:
    manifest = phase1_manifest()

    payload = manifest.to_dict()
    restored = BenchmarkManifest.from_dict(payload)

    assert restored.to_dict()["scenarios"] == payload["scenarios"]
    assert restored.scenario_ids() == manifest.scenario_ids()
    assert payload["coverage"] == manifest.coverage_summary().to_dict()
    assert payload["coverage"]["total_scenarios"] == 8
    assert payload["coverage"]["by_family"] == {
        "graphqli": 1,
        "nosqli": 1,
        "sqli": 5,
        "websocket": 1,
    }
    assert payload["coverage"]["by_body_format"] == {
        "form": 2,
        "json": 4,
        "multipart": 1,
        "xml": 1,
    }
    assert payload["coverage"]["by_expected_kind"]["sqli-error"] == 3
    assert payload["coverage"]["live_services_required"] == 1


def test_benchmark_catalog_builds_stealthix_scan_targets() -> None:
    catalog = BenchmarkFixtureCatalog.phase1()

    auth_target = catalog.build_scan_target("sqli.rest.auth.mssql.error", "http://127.0.0.1:8080")
    websocket_target = catalog.build_scan_target(
        "websocket.sqli.postgresql.timing", "http://127.0.0.1:8080"
    )

    assert catalog.expected_finding_kinds("nosqli.rest.json.mongodb.operator") == ["nosqli-mongodb"]
    assert "requires bearer auth" in catalog.target_description("sqli.rest.auth.mssql.error")
    assert auth_target["url"] == "http://127.0.0.1:8080/admin/audit?id=1"
    assert auth_target["auth_type"] == "bearer"
    assert auth_target["metadata"]["benchmark"]["dbms_family"] == "mssql"
    assert websocket_target["ws_url"] == "ws://127.0.0.1:8080/ws/search"
    assert websocket_target["ws_messages"] == ['{"op":"search","q":"books"}']


def test_runner_records_matches_confidence_failures_skips_and_tool_status() -> None:
    manifest = phase1_manifest()
    base_urls = {
        "sqli.rest.query.mysql.error": "http://fixture.test",
        "sqli.rest.json.postgresql.boolean": "http://fixture.test",
    }

    def fake_scan(scenario, scan_target):
        confidence = (
            "low" if scenario.scenario_id == "sqli.rest.json.postgresql.boolean" else "high"
        )
        finding = Finding(
            kind=scenario.expected_findings[0].kind,
            target=scan_target["url"],
            parameter=(scan_target["target_params"] or [None])[0],
            location="query",
            details={"confidence": confidence},
        )
        return ScanResult(target=scan_target["url"], findings=[finding], metadata={})

    report = run_benchmark(
        manifest,
        base_urls=base_urls,
        scan_func=fake_scan,
        external_tools=(ExternalToolSpec("missing competitor", "stealthix-definitely-missing"),),
    )
    payload = report.to_dict()
    records = {item["scenario_id"]: item for item in payload["records"]}

    assert payload["summary"] == {
        "total_records": 8,
        "completed": 2,
        "skipped": 6,
        "errors": 0,
        "passed": 1,
        "failed": 1,
    }
    assert records["sqli.rest.query.mysql.error"]["passed"] is True
    failed = records["sqli.rest.json.postgresql.boolean"]
    assert failed["passed"] is False
    assert failed["confidence_failures"] == [
        {"kind": "sqli-boolean", "required": "high", "observed": "low"}
    ]
    assert records["nosqli.rest.json.mongodb.operator"]["status"] == "skipped"
    assert payload["external_tools"] == [
        {
            "name": "missing competitor",
            "executable": "stealthix-definitely-missing",
            "installed": False,
            "resolved_path": None,
            "args": [],
        }
    ]
