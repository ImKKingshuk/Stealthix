"""Benchmark manifest models for reproducible scanner comparisons."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Self

CONFIDENCE_RANK = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "confirmed": 4,
}


@dataclass(frozen=True)
class ExpectedFinding:
    """Expected scanner output for a vulnerable benchmark scenario."""

    kind: str
    minimum_confidence: str = "medium"
    required: bool = True

    def __post_init__(self) -> None:
        confidence = self.minimum_confidence.lower()
        if confidence not in CONFIDENCE_RANK:
            raise ValueError(f"Unsupported confidence level: {self.minimum_confidence}")
        object.__setattr__(self, "minimum_confidence", confidence)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "minimum_confidence": self.minimum_confidence,
            "required": self.required,
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        return cls(
            kind=str(payload["kind"]),
            minimum_confidence=str(payload.get("minimum_confidence") or "medium"),
            required=bool(payload.get("required", True)),
        )


@dataclass(frozen=True)
class BenchmarkTarget:
    """HTTP/WebSocket target metadata used to construct a scan request."""

    description: str
    method: str = "GET"
    path: str = "/"
    body_format: str = "form"
    data: dict[str, Any] | None = None
    headers: dict[str, str] = field(default_factory=dict)
    target_params: tuple[str, ...] = ()
    auth_required: bool = False
    websocket_messages: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "method", self.method.upper())
        object.__setattr__(self, "body_format", self.body_format.lower())
        object.__setattr__(self, "headers", dict(self.headers))
        object.__setattr__(self, "target_params", tuple(self.target_params))
        object.__setattr__(self, "websocket_messages", tuple(self.websocket_messages))

    def to_dict(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "method": self.method,
            "path": self.path,
            "body_format": self.body_format,
            "data": dict(self.data) if isinstance(self.data, dict) else None,
            "headers": dict(self.headers),
            "target_params": list(self.target_params),
            "auth_required": self.auth_required,
            "websocket_messages": list(self.websocket_messages),
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        return cls(
            description=str(payload["description"]),
            method=str(payload.get("method") or "GET"),
            path=str(payload.get("path") or "/"),
            body_format=str(payload.get("body_format") or "form"),
            data=dict(payload["data"]) if isinstance(payload.get("data"), dict) else None,
            headers={str(k): str(v) for k, v in dict(payload.get("headers") or {}).items()},
            target_params=tuple(str(item) for item in payload.get("target_params") or ()),
            auth_required=bool(payload.get("auth_required", False)),
            websocket_messages=tuple(str(item) for item in payload.get("websocket_messages") or ()),
        )


@dataclass(frozen=True)
class BenchmarkScenario:
    """A single vulnerable scenario in the benchmark manifest."""

    scenario_id: str
    title: str
    family: str
    dbms_family: str
    target: BenchmarkTarget
    expected_findings: tuple[ExpectedFinding, ...]
    live_services_required: bool = False
    tags: tuple[str, ...] = ()
    notes: str | None = None

    def __post_init__(self) -> None:
        if not self.scenario_id:
            raise ValueError("scenario_id is required")
        if not self.expected_findings:
            raise ValueError(f"{self.scenario_id} must declare expected findings")
        object.__setattr__(self, "family", self.family.lower())
        object.__setattr__(self, "dbms_family", self.dbms_family.lower())
        object.__setattr__(self, "expected_findings", tuple(self.expected_findings))
        object.__setattr__(self, "tags", tuple(str(item).lower() for item in self.tags))

    def to_dict(self) -> dict[str, Any]:
        payload = {
            "scenario_id": self.scenario_id,
            "title": self.title,
            "family": self.family,
            "dbms_family": self.dbms_family,
            "target": self.target.to_dict(),
            "expected_findings": [finding.to_dict() for finding in self.expected_findings],
            "live_services_required": self.live_services_required,
            "tags": list(self.tags),
        }
        if self.notes is not None:
            payload["notes"] = self.notes
        return payload

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        return cls(
            scenario_id=str(payload["scenario_id"]),
            title=str(payload["title"]),
            family=str(payload["family"]),
            dbms_family=str(payload["dbms_family"]),
            target=BenchmarkTarget.from_dict(dict(payload["target"])),
            expected_findings=tuple(
                ExpectedFinding.from_dict(dict(item)) for item in payload["expected_findings"]
            ),
            live_services_required=bool(payload.get("live_services_required", False)),
            tags=tuple(str(item) for item in payload.get("tags") or ()),
            notes=str(payload["notes"]) if payload.get("notes") is not None else None,
        )


@dataclass(frozen=True)
class CoverageSummary:
    """Machine-readable expected coverage accounting."""

    total_scenarios: int
    by_family: dict[str, int]
    by_dbms_family: dict[str, int]
    by_body_format: dict[str, int]
    by_expected_kind: dict[str, int]
    live_services_required: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_scenarios": self.total_scenarios,
            "by_family": dict(self.by_family),
            "by_dbms_family": dict(self.by_dbms_family),
            "by_body_format": dict(self.by_body_format),
            "by_expected_kind": dict(self.by_expected_kind),
            "live_services_required": self.live_services_required,
        }


@dataclass(frozen=True)
class BenchmarkManifest:
    """Versioned benchmark scenario manifest."""

    manifest_id: str
    version: str
    scenarios: tuple[BenchmarkScenario, ...]
    description: str = ""

    def __post_init__(self) -> None:
        ids = [scenario.scenario_id for scenario in self.scenarios]
        if len(ids) != len(set(ids)):
            duplicates = sorted({item for item in ids if ids.count(item) > 1})
            raise ValueError(f"Duplicate benchmark scenario IDs: {duplicates}")
        object.__setattr__(self, "scenarios", tuple(self.scenarios))

    def scenario_ids(self) -> list[str]:
        return [scenario.scenario_id for scenario in self.scenarios]

    def get(self, scenario_id: str) -> BenchmarkScenario:
        for scenario in self.scenarios:
            if scenario.scenario_id == scenario_id:
                return scenario
        raise KeyError(f"Unknown benchmark scenario: {scenario_id}")

    def coverage_summary(self) -> CoverageSummary:
        return CoverageSummary(
            total_scenarios=len(self.scenarios),
            by_family=dict(sorted(Counter(s.family for s in self.scenarios).items())),
            by_dbms_family=dict(sorted(Counter(s.dbms_family for s in self.scenarios).items())),
            by_body_format=dict(
                sorted(Counter(s.target.body_format for s in self.scenarios).items())
            ),
            by_expected_kind=dict(
                sorted(
                    Counter(
                        finding.kind
                        for scenario in self.scenarios
                        for finding in scenario.expected_findings
                    ).items()
                )
            ),
            live_services_required=sum(
                1 for scenario in self.scenarios if scenario.live_services_required
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_id": self.manifest_id,
            "version": self.version,
            "description": self.description,
            "coverage": self.coverage_summary().to_dict(),
            "scenarios": [scenario.to_dict() for scenario in self.scenarios],
        }

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> Self:
        return cls(
            manifest_id=str(payload["manifest_id"]),
            version=str(payload["version"]),
            description=str(payload.get("description") or ""),
            scenarios=tuple(
                BenchmarkScenario.from_dict(dict(item)) for item in payload.get("scenarios") or ()
            ),
        )
