"""Deterministic benchmark scenario catalog and local target builder."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urljoin

from stealthix.benchmarks.models import (
    BenchmarkManifest,
    BenchmarkScenario,
    BenchmarkTarget,
    ExpectedFinding,
)

PHASE1_MANIFEST_ID = "stealthix.phase1.vulnerable-foundation"


def phase1_manifest() -> BenchmarkManifest:
    """Return the built-in Phase 1 vulnerable benchmark manifest."""

    return BenchmarkManifest(
        manifest_id=PHASE1_MANIFEST_ID,
        version="1.0",
        description=(
            "Reproducible vulnerable target catalog for SQLi, NoSQLi, graph query "
            "injection, WebSocket mutation, and REST JSON/XML/multipart/auth flows."
        ),
        scenarios=(
            BenchmarkScenario(
                scenario_id="sqli.rest.query.mysql.error",
                title="MySQL error-based SQLi through REST query parameter",
                family="sqli",
                dbms_family="mysql",
                target=BenchmarkTarget(
                    description="GET /rest/products?id=1 reflects MySQL syntax errors for quoted IDs.",
                    method="GET",
                    path="/rest/products?id=1",
                    body_format="form",
                    target_params=("id",),
                ),
                expected_findings=(ExpectedFinding("sqli-error", minimum_confidence="high"),),
                tags=("rest", "query", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="sqli.rest.json.postgresql.boolean",
                title="PostgreSQL boolean SQLi through REST JSON body",
                family="sqli",
                dbms_family="postgresql",
                target=BenchmarkTarget(
                    description="POST /api/search accepts JSON filter expression with injectable term.",
                    method="POST",
                    path="/api/search",
                    body_format="json",
                    data={"term": "books", "tenant": "blue"},
                    headers={"Content-Type": "application/json"},
                    target_params=("term",),
                ),
                expected_findings=(ExpectedFinding("sqli-boolean", minimum_confidence="high"),),
                tags=("rest", "json", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="nosqli.rest.json.mongodb.operator",
                title="MongoDB operator injection through REST JSON body",
                family="nosqli",
                dbms_family="mongodb",
                target=BenchmarkTarget(
                    description="POST /api/users/search accepts unsanitized JSON selector operators.",
                    method="POST",
                    path="/api/users/search",
                    body_format="json",
                    data={"username": "alice", "active": True},
                    headers={"Content-Type": "application/json"},
                    target_params=("username",),
                ),
                expected_findings=(ExpectedFinding("nosqli-mongodb", minimum_confidence="high"),),
                tags=("rest", "json", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="graphqli.rest.json.neo4j.cypher",
                title="Neo4j Cypher injection through GraphQL-style JSON query",
                family="graphqli",
                dbms_family="neo4j",
                target=BenchmarkTarget(
                    description="POST /graphql passes user-controlled GraphQL variables into Cypher.",
                    method="POST",
                    path="/graphql",
                    body_format="json",
                    data={
                        "query": "query($name:String){ user(name:$name){ id } }",
                        "name": "alice",
                    },
                    headers={"Content-Type": "application/json"},
                    target_params=("name",),
                ),
                expected_findings=(ExpectedFinding("graphqli-neo4j", minimum_confidence="medium"),),
                tags=("graphql", "json", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="websocket.sqli.postgresql.timing",
                title="PostgreSQL timing SQLi through WebSocket JSON message",
                family="websocket",
                dbms_family="postgresql",
                target=BenchmarkTarget(
                    description="ws /ws/search accepts JSON messages with injectable search value.",
                    method="GET",
                    path="/ws/search",
                    body_format="json",
                    target_params=("q",),
                    websocket_messages=('{"op":"search","q":"books"}',),
                ),
                expected_findings=(ExpectedFinding("websocket-time", minimum_confidence="medium"),),
                live_services_required=True,
                tags=("websocket", "json"),
            ),
            BenchmarkScenario(
                scenario_id="sqli.rest.xml.oracle.error",
                title="Oracle SQLi through REST XML body",
                family="sqli",
                dbms_family="oracle",
                target=BenchmarkTarget(
                    description="PUT /api/xml/order parses XML order IDs into an Oracle query.",
                    method="PUT",
                    path="/api/xml/order",
                    body_format="xml",
                    data={"orderId": "1001"},
                    headers={"Content-Type": "application/xml"},
                    target_params=("orderId",),
                ),
                expected_findings=(ExpectedFinding("sqli-error", minimum_confidence="medium"),),
                tags=("rest", "xml", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="sqli.rest.multipart.mysql.filemeta",
                title="MySQL SQLi through multipart metadata field",
                family="sqli",
                dbms_family="mysql",
                target=BenchmarkTarget(
                    description="POST /api/upload trusts multipart title metadata in a MySQL lookup.",
                    method="POST",
                    path="/api/upload",
                    body_format="multipart",
                    data={"file": "sample.txt", "title": "report"},
                    target_params=("title",),
                ),
                expected_findings=(ExpectedFinding("sqli-boolean", minimum_confidence="medium"),),
                tags=("rest", "multipart", "local-mock"),
            ),
            BenchmarkScenario(
                scenario_id="sqli.rest.auth.mssql.error",
                title="MSSQL SQLi behind bearer-auth REST endpoint",
                family="sqli",
                dbms_family="mssql",
                target=BenchmarkTarget(
                    description="GET /admin/audit?id=1 requires bearer auth before reaching MSSQL query.",
                    method="GET",
                    path="/admin/audit?id=1",
                    body_format="form",
                    headers={"Authorization": "Bearer benchmark-token"},
                    target_params=("id",),
                    auth_required=True,
                ),
                expected_findings=(ExpectedFinding("sqli-error", minimum_confidence="high"),),
                tags=("rest", "auth", "local-mock"),
            ),
        ),
    )


@dataclass(frozen=True)
class BenchmarkFixtureCatalog:
    """Maps scenario IDs to expected metadata and scan target descriptions."""

    manifest: BenchmarkManifest

    @classmethod
    def phase1(cls) -> BenchmarkFixtureCatalog:
        return cls(phase1_manifest())

    def scenario_ids(self) -> list[str]:
        return self.manifest.scenario_ids()

    def expected_finding_kinds(self, scenario_id: str) -> list[str]:
        scenario = self.manifest.get(scenario_id)
        return [finding.kind for finding in scenario.expected_findings]

    def target_description(self, scenario_id: str) -> str:
        return self.manifest.get(scenario_id).target.description

    def build_scan_target(self, scenario_id: str, base_url: str) -> dict[str, Any]:
        """Build a Stealthix-compatible scan target dictionary for a local fixture URL."""

        scenario = self.manifest.get(scenario_id)
        target = scenario.target
        url = _join_target_url(base_url, target.path)
        metadata = {
            "origin": "benchmark-catalog",
            "benchmark": {
                "manifest_id": self.manifest.manifest_id,
                "version": self.manifest.version,
                "scenario_id": scenario.scenario_id,
                "family": scenario.family,
                "dbms_family": scenario.dbms_family,
                "expected_finding_kinds": [item.kind for item in scenario.expected_findings],
                "minimum_confidence": {
                    item.kind: item.minimum_confidence for item in scenario.expected_findings
                },
                "live_services_required": scenario.live_services_required,
            },
        }
        spec = {
            "url": url,
            "method": target.method,
            "headers": dict(target.headers),
            "data": dict(target.data) if isinstance(target.data, dict) else None,
            "body_format": target.body_format,
            "target_params": list(target.target_params),
            "metadata": metadata,
        }
        if target.auth_required:
            spec["auth_type"] = "bearer"
            spec["auth_token"] = "benchmark-token"
        if target.websocket_messages:
            spec["ws_url"] = url.replace("http://", "ws://").replace("https://", "wss://", 1)
            spec["ws_messages"] = list(target.websocket_messages)
        return spec

    def build_scan_targets(self, base_urls: dict[str, str]) -> dict[str, dict[str, Any]]:
        return {
            scenario_id: self.build_scan_target(scenario_id, base_url)
            for scenario_id, base_url in base_urls.items()
        }


def _join_target_url(base_url: str, path: str) -> str:
    if base_url.startswith(("ws://", "wss://")):
        return base_url.rstrip("/") + "/" + path.lstrip("/")
    return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
