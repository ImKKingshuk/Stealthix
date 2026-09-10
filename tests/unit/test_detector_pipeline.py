from stealthix.core.detector_pipeline import (
    DetectionStage,
    DetectionTask,
    DetectorPipelineExecutor,
    RuntimePlanner,
    task_key,
)
from stealthix.core.models import Finding, TargetParam
from stealthix.core.session import ScanSession, SessionConfig


def test_runtime_planner_preserves_dbms_routing(monkeypatch):
    points = [TargetParam(name="id", location="query")]
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql"))
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: points,
    ).prepare()

    assert [stage.phase for stage in plan.stages] == ["SQLi Detection"]
    assert plan.selected_targets == tuple(points)


def test_runtime_planner_preserves_unknown_dbms_fallback(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: [],
    ).prepare()

    assert [stage.phase for stage in plan.stages] == [
        "SQLi Detection",
        "NoSQL Detection",
        "NewSQL Detection",
    ]


def test_runtime_planner_routes_search_backends_to_searchqli(monkeypatch):
    points = [TargetParam(name="q", location="query")]
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="elasticsearch"))
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: points,
    ).prepare()

    assert [stage.phase for stage in plan.stages] == ["SearchQLi Detection"]
    assert [task.detector for task in plan.stages[0].tasks] == ["Search injection detection"]


def test_runtime_planner_routes_plugin_graph_family_to_graphqli(monkeypatch):
    points = [TargetParam(name="filter", location="query")]
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    monkeypatch.setattr(
        "stealthix.plugins.runtime.apply_plugin",
        lambda _session: {"name": "neo4j", "family": "graph", "dbms": "neo4j"},
    )

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: points,
    ).prepare()

    assert [stage.phase for stage in plan.stages] == ["GraphQLi Detection"]
    assert [task.detector for task in plan.stages[0].tasks] == ["Graph injection detection"]


def test_runtime_planner_routes_timeseries_without_generic_nosql(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="prometheus"))
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: [],
    ).prepare()

    assert [stage.phase for stage in plan.stages] == ["TimeSeriesQLi Detection"]


def test_runtime_planner_preserves_newsql_yugabyte_routing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="yugabyte_ycql"))
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: [],
    ).prepare()

    assert [stage.phase for stage in plan.stages] == ["NewSQL Detection"]


def test_runtime_planner_keeps_api_graphql_and_websocket_level_gates(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/graphql",
            dbms="mysql",
            level=3,
            ws_url="ws://example.com/socket",
        )
    )
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)

    plan = RuntimePlanner(
        session,
        emit_progress=lambda **_payload: None,
        recon_enabled=lambda: False,
        run_reconnaissance=lambda: None,
        discover_targets=lambda _session: [],
    ).prepare()

    assert [stage.phase for stage in plan.stages] == [
        "SQLi Detection",
        "IDOR Checks",
        "GraphQL Checks",
        "WebSocket Checks",
    ]


def test_pipeline_task_key_matches_resume_contract():
    target = TargetParam(name="id", location="query")
    task = DetectionTask(
        order=2, detector="SQL injection detection", target=target, run=lambda _: []
    )
    stage = DetectionStage(phase="SQLi Detection", message="Running SQLi…", tasks=(task,))

    assert task_key(stage, task) == "SQLi Detection|SQL injection detection|query:id|2"


def test_pipeline_executor_checkpoints_after_each_task():
    session = ScanSession(SessionConfig(base_url="http://example.com", threads=1))
    target = TargetParam(name="id", location="query")
    checkpoints: list[dict[str, object]] = []
    progress: list[dict[str, object]] = []

    def run(worker_session):
        worker_session.metadata["worker_marker"] = ["done"]
        return [Finding(kind="sqli", target="http://example.com/?id=1", parameter="id")]

    task = DetectionTask(order=0, detector="SQL injection detection", target=target, run=run)
    stage = DetectionStage(phase="SQLi Detection", message="Running SQLi…", tasks=(task,))
    executor = DetectorPipelineExecutor(
        session,
        emit_progress=lambda **payload: progress.append(payload),
        save_detect_checkpoint=lambda **payload: checkpoints.append(payload),
    )

    findings, completed, completed_ids = executor.execute_stage(
        stage,
        findings_so_far=[],
        completed_tasks=0,
        total_tasks=1,
        completed_task_ids=[],
        all_task_ids=[task_key(stage, task)],
    )

    assert completed == 1
    assert completed_ids == [task_key(stage, task)]
    assert findings[0].kind == "sqli"
    assert session.metadata["worker_marker"] == ["done"]
    assert checkpoints[-1]["completed_task_ids"] == completed_ids
    assert progress[-1]["detector"] == "SQL injection detection"


def test_pipeline_stage_condition_skips_work():
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    called = False

    def run(_session):
        nonlocal called
        called = True
        return []

    task = DetectionTask(order=0, detector="plugin checks", target=None, run=run)
    stage = DetectionStage(
        phase="Plugin Checks",
        message="Running plugin checks…",
        tasks=(task,),
        condition=lambda findings: any(item.kind.startswith("sqli") for item in findings),
    )
    executor = DetectorPipelineExecutor(
        session,
        emit_progress=lambda **_payload: None,
        save_detect_checkpoint=lambda **_payload: None,
    )

    findings, completed, completed_ids = executor.execute_stage(
        stage,
        findings_so_far=[Finding(kind="nosqli", target="t")],
        completed_tasks=0,
        total_tasks=1,
        completed_task_ids=[],
        all_task_ids=[task_key(stage, task)],
    )

    assert findings == []
    assert completed == 0
    assert completed_ids == []
    assert called is False
