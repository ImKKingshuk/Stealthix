"""Detector planning and execution primitives for the scan engine."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, cast

import structlog

from stealthix.core.errors import DetectionError
from stealthix.core.models import Finding, TargetParam
from stealthix.core.session import ScanSession
from stealthix.core.targeting import discover_target_params

ProgressEmitter = Callable[..., None]
CheckpointSaver = Callable[..., None]

_SQL_DBMS = {"mysql", "postgresql", "postgres", "mssql", "oracle", "sqlite", "mariadb", "db2"}
_NOSQL_DBMS = {
    "mongodb",
    "mongo",
    "documentdb",
    "couchdb",
    "couchbase",
    "redis",
    "cassandra",
    "firebase",
    "dynamodb",
    "cosmosdb",
    "cosmos",
}
_NEWSQL_DBMS = {
    "cockroachdb",
    "cockroach",
    "tidb",
    "voltdb",
    "spanner",
    "yugabyte",
    "yugabytedb",
    "ycql",
    "yugabyte-ycql",
    "yugabyte_ycql",
}
_SEARCH_DBMS = {"elasticsearch", "opensearch", "solr"}
_GRAPH_DBMS = {"neo4j", "janusgraph", "neptune"}
_TIMESERIES_DBMS = {"influxdb", "prometheus"}
_SEARCH_FAMILIES = {"search", "searchql", "searchqli"}
_GRAPH_FAMILIES = {"graph", "graphdb", "graphqli"}
_TIMESERIES_FAMILIES = {"timeseries", "time-series", "timeseriesql", "timeseriesqli"}
_NOSQL_FAMILIES = {"nosql", "document", "keyvalue", "key-value", "multimodel", "multi-model"}
_NEWSQL_FAMILIES = {"newsql"}


@dataclass(frozen=True)
class DetectionTask:
    order: int
    detector: str
    target: TargetParam | None
    run: Callable[[ScanSession], list[Finding]]


@dataclass(frozen=True)
class DetectionStage:
    phase: str
    message: str
    tasks: tuple[DetectionTask, ...]
    condition: Callable[[list[Finding]], bool] | None = None


@dataclass(frozen=True)
class RuntimePlan:
    plugin: dict[str, Any] | None
    discovered_targets: tuple[TargetParam, ...]
    selected_targets: tuple[TargetParam, ...]
    stages: tuple[DetectionStage, ...]
    all_task_ids: tuple[str, ...]


@dataclass(frozen=True)
class DelegatedScan(Exception):
    targets: list[dict[str, Any]]


def task_key(stage: DetectionStage, task: DetectionTask) -> str:
    target = f"{task.target.location}:{task.target.name}" if task.target is not None else "global"
    return f"{stage.phase}|{task.detector}|{target}|{task.order}"


def flatten_stage_results(stage_results: list[tuple[int, list[Finding]]]) -> list[Finding]:
    ordered = [items for _, items in sorted(stage_results, key=lambda entry: entry[0])]
    return [finding for items in ordered for finding in items]


def _plugin_dbms_names(plugin: dict[str, Any] | None) -> set[str]:
    if not isinstance(plugin, dict):
        return set()
    names: set[str] = set()
    for key in ("dbms", "name", "backend"):
        value = plugin.get(key)
        if isinstance(value, str) and value.strip():
            names.add(value.strip().lower())
    return names


def _plugin_family_names(plugin: dict[str, Any] | None) -> set[str]:
    if not isinstance(plugin, dict):
        return set()
    names: set[str] = set()
    for key in ("family", "category", "type"):
        value = plugin.get(key)
        if isinstance(value, str) and value.strip():
            names.add(value.strip().lower())
    return names


class RuntimePlanner:
    """Build an executable detector plan from session runtime state."""

    def __init__(
        self,
        session: ScanSession,
        *,
        emit_progress: ProgressEmitter,
        recon_enabled: Callable[[], bool],
        run_reconnaissance: Callable[[], None],
        discover_targets: Callable[[ScanSession], list[TargetParam]] = discover_target_params,
    ) -> None:
        self.session = session
        self.emit_progress = emit_progress
        self.recon_enabled = recon_enabled
        self.run_reconnaissance = run_reconnaissance
        self.discover_targets = discover_targets

    def prepare(self) -> RuntimePlan:
        from stealthix.detection.common import detect_idor
        from stealthix.detection.graphql import detect_graphql
        from stealthix.detection.graphqli import detect_graphqli
        from stealthix.detection.newsql import detect_newsql
        from stealthix.detection.nosqli import detect_nosqli
        from stealthix.detection.rest_api import load_api_targets_for_session
        from stealthix.detection.searchqli import detect_searchqli
        from stealthix.detection.sqli import detect_sqli
        from stealthix.detection.timeseriesqli import detect_timeseriesqli
        from stealthix.detection.websocket import detect_websocket, websocket_enabled
        from stealthix.plugins.runtime import apply_plugin, run_plugin_checks

        if self.session.config.api_schema and not self.session.runtime.get("api_import_expanded"):
            imported_targets = load_api_targets_for_session(self.session)
            if imported_targets:
                self.session.runtime["api_import_expanded"] = True
                raise DelegatedScan(imported_targets)

        if self.session.config.level >= 2 and self.recon_enabled():
            self.run_reconnaissance()

        self.emit_progress(
            phase="Fingerprint / Plugin",
            message="Applying plugin detection…",
            progress_percent=5,
        )
        plugin_dict = apply_plugin(self.session)
        discovered = tuple(self.discover_targets(self.session))
        chosen = discovered
        if self.session.config.target_params:
            requested = {
                str(name).strip() for name in self.session.config.target_params if str(name).strip()
            }
            chosen = tuple(point for point in discovered if point.name in requested) or discovered
        targets: tuple[TargetParam | None, ...] = cast(
            tuple[TargetParam | None, ...], chosen or (None,)
        )

        def build_param_stage(
            phase: str,
            detector: str,
            callback: Callable[[ScanSession, TargetParam | None], list[Finding]],
        ) -> DetectionStage:
            return DetectionStage(
                phase=phase,
                message=f"Running {detector}…",
                tasks=tuple(
                    DetectionTask(
                        order=index,
                        detector=detector,
                        target=point,
                        run=lambda worker, point=point, callback=callback: callback(worker, point),
                    )
                    for index, point in enumerate(targets)
                ),
            )

        stages: list[DetectionStage] = []
        configured_dbms = (self.session.config.dbms or "").strip().lower()
        dbms_names = ({configured_dbms} if configured_dbms else set()) | _plugin_dbms_names(
            plugin_dict
        )
        family_names = _plugin_family_names(plugin_dict)

        has_search = bool(dbms_names & _SEARCH_DBMS or family_names & _SEARCH_FAMILIES)
        has_graph = bool(dbms_names & _GRAPH_DBMS or family_names & _GRAPH_FAMILIES)
        has_timeseries = bool(dbms_names & _TIMESERIES_DBMS or family_names & _TIMESERIES_FAMILIES)
        has_sql = bool(dbms_names & _SQL_DBMS)
        has_newsql = bool(dbms_names & _NEWSQL_DBMS or family_names & _NEWSQL_FAMILIES)
        has_generic_nosql = bool(
            (dbms_names & _NOSQL_DBMS or family_names & _NOSQL_FAMILIES)
            and not (has_search or has_graph or has_timeseries)
        )

        if has_sql:
            stages.append(
                build_param_stage("SQLi Detection", "SQL injection detection", detect_sqli)
            )
        elif has_search:
            stages.append(
                build_param_stage(
                    "SearchQLi Detection", "Search injection detection", detect_searchqli
                )
            )
        elif has_graph:
            stages.append(
                build_param_stage(
                    "GraphQLi Detection", "Graph injection detection", detect_graphqli
                )
            )
        elif has_timeseries:
            stages.append(
                build_param_stage(
                    "TimeSeriesQLi Detection",
                    "time-series injection detection",
                    detect_timeseriesqli,
                )
            )
        elif has_generic_nosql:
            stages.append(
                build_param_stage("NoSQL Detection", "NoSQL injection detection", detect_nosqli)
            )
        elif has_newsql:
            stages.append(
                build_param_stage("NewSQL Detection", "NewSQL injection detection", detect_newsql)
            )
        else:
            stages.extend(
                [
                    build_param_stage("SQLi Detection", "SQL injection detection", detect_sqli),
                    build_param_stage(
                        "NoSQL Detection", "NoSQL injection detection", detect_nosqli
                    ),
                    build_param_stage(
                        "NewSQL Detection", "NewSQL injection detection", detect_newsql
                    ),
                ]
            )
        if self.session.config.level >= 2:
            stages.append(build_param_stage("IDOR Checks", "IDOR checks", detect_idor))
        if self.session.config.level >= 3:
            stages.append(
                DetectionStage(
                    phase="GraphQL Checks",
                    message="Running GraphQL checks…",
                    tasks=(
                        DetectionTask(
                            order=0,
                            detector="GraphQL checks",
                            target=None,
                            run=lambda worker: detect_graphql(worker),
                        ),
                    ),
                )
            )
        if websocket_enabled(self.session):
            stages.append(
                DetectionStage(
                    phase="WebSocket Checks",
                    message="Running WebSocket checks…",
                    tasks=(
                        DetectionTask(
                            order=0,
                            detector="WebSocket checks",
                            target=None,
                            run=lambda worker: detect_websocket(worker),
                        ),
                    ),
                )
            )
        if plugin_dict and self.session.config.level >= 2:
            stages.append(
                DetectionStage(
                    phase="Plugin Checks",
                    message="Running plugin checks…",
                    tasks=(
                        DetectionTask(
                            order=0,
                            detector="plugin checks",
                            target=None,
                            run=lambda worker, plugin=plugin_dict: run_plugin_checks(
                                worker, plugin
                            ),
                        ),
                    ),
                    condition=lambda findings: any(
                        item.kind.startswith("sqli") for item in findings
                    ),
                )
            )

        total_tasks = sum(len(stage.tasks) for stage in stages)
        self.emit_progress(
            phase="Planning",
            message=f"Prepared {len(chosen) or 1} parameter(s) across {total_tasks or 1} task(s).",
            progress_percent=10,
            discovered_params=len(discovered),
            selected_params=len(chosen) if chosen else 1,
            total_tasks=total_tasks,
        )
        frozen_stages = tuple(stages)
        return RuntimePlan(
            plugin=plugin_dict,
            discovered_targets=discovered,
            selected_targets=chosen,
            stages=frozen_stages,
            all_task_ids=tuple(
                task_key(stage, task) for stage in frozen_stages for task in stage.tasks
            ),
        )


class DetectorPipelineExecutor:
    """Execute detector stages with worker-session isolation and checkpoints."""

    def __init__(
        self,
        session: ScanSession,
        *,
        emit_progress: ProgressEmitter,
        save_detect_checkpoint: CheckpointSaver,
        logger: Any | None = None,
    ) -> None:
        self.session = session
        self.emit_progress = emit_progress
        self.save_detect_checkpoint = save_detect_checkpoint
        self.logger = logger or structlog.get_logger(__name__)

    def execute_task(self, task: DetectionTask) -> tuple[int, list[Finding], ScanSession]:
        worker_session = self.session.clone_for_worker()
        worker_session.control.wait_if_paused()
        findings = task.run(worker_session)
        return task.order, findings, worker_session

    def execute_stage(
        self,
        stage: DetectionStage,
        *,
        findings_so_far: list[Finding],
        completed_tasks: int,
        total_tasks: int,
        completed_task_ids: list[str],
        all_task_ids: list[str],
    ) -> tuple[list[Finding], int, list[str]]:
        if stage.condition is not None and not stage.condition(findings_so_far):
            return [], completed_tasks, completed_task_ids

        self.emit_progress(
            phase=stage.phase,
            message=stage.message,
            progress_percent=10 + int((completed_tasks * 89) / max(1, total_tasks)),
            completed_tasks=completed_tasks,
            total_tasks=total_tasks,
            finding_count=len(findings_so_far),
        )

        if not stage.tasks:
            return [], completed_tasks, completed_task_ids

        stage_results: list[tuple[int, list[Finding]]] = []
        workers = min(self.session.config.worker_count(), len(stage.tasks))

        if workers <= 1:
            for task in stage.tasks:
                order, task_findings, worker_session = self.execute_task(task)
                self.session.merge_worker_state(worker_session)
                completed_tasks = self._record_task_completion(
                    stage=stage,
                    task=task,
                    order=order,
                    task_findings=task_findings,
                    stage_results=stage_results,
                    findings_so_far=findings_so_far,
                    completed_tasks=completed_tasks,
                    total_tasks=total_tasks,
                    completed_task_ids=completed_task_ids,
                    all_task_ids=all_task_ids,
                )
            return flatten_stage_results(stage_results), completed_tasks, completed_task_ids

        with ThreadPoolExecutor(
            max_workers=workers, thread_name_prefix="stealthix-scan"
        ) as executor:
            futures: dict[Future[tuple[int, list[Finding], ScanSession]], DetectionTask] = {
                executor.submit(self.execute_task, task): task for task in stage.tasks
            }
            try:
                for future in as_completed(futures):
                    task = futures[future]
                    order, task_findings, worker_session = future.result()
                    self.session.merge_worker_state(worker_session)
                    completed_tasks = self._record_task_completion(
                        stage=stage,
                        task=task,
                        order=order,
                        task_findings=task_findings,
                        stage_results=stage_results,
                        findings_so_far=findings_so_far,
                        completed_tasks=completed_tasks,
                        total_tasks=total_tasks,
                        completed_task_ids=completed_task_ids,
                        all_task_ids=all_task_ids,
                    )
            except (KeyboardInterrupt, SystemExit):
                for future in futures:
                    future.cancel()
                raise
            except DetectionError as e:
                self.logger.error(
                    "stage_execution_error",
                    stage=stage.phase,
                    error=str(e),
                    exc_info=True,
                )
                for future in futures:
                    future.cancel()
                raise DetectionError(f"Stage execution failed: {e}") from e

        return flatten_stage_results(stage_results), completed_tasks, completed_task_ids

    def _record_task_completion(
        self,
        *,
        stage: DetectionStage,
        task: DetectionTask,
        order: int,
        task_findings: list[Finding],
        stage_results: list[tuple[int, list[Finding]]],
        findings_so_far: list[Finding],
        completed_tasks: int,
        total_tasks: int,
        completed_task_ids: list[str],
        all_task_ids: list[str],
    ) -> int:
        stage_results.append((order, task_findings))
        completed_tasks += 1
        completed_task_ids.append(task_key(stage, task))
        flattened = flatten_stage_results(stage_results)
        self.emit_progress(
            phase=stage.phase,
            message=stage.message,
            progress_percent=10 + int((completed_tasks * 89) / max(1, total_tasks)),
            completed_tasks=completed_tasks,
            total_tasks=total_tasks,
            finding_count=len(findings_so_far) + len(flattened),
            detector=task.detector,
            target_param=task.target.name if task.target else None,
        )
        self.save_detect_checkpoint(
            stage_phase=stage.phase,
            findings=[*findings_so_far, *flattened],
            completed_task_ids=completed_task_ids,
            all_task_ids=all_task_ids,
            total_tasks=total_tasks,
        )
        return completed_tasks


__all__ = [
    "DelegatedScan",
    "DetectionStage",
    "DetectionTask",
    "DetectorPipelineExecutor",
    "RuntimePlan",
    "RuntimePlanner",
    "flatten_stage_results",
    "task_key",
]
