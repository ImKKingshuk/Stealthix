import asyncio
import threading

from stealthix.core.async_engine import AsyncEngine
from stealthix.core.checkpoint import CheckpointManager, load_checkpoint
from stealthix.core.engine import Engine
from stealthix.core.models import Finding, ScanResult, TargetParam
from stealthix.core.session import ScanSession, SessionConfig


def test_engine_dbms_routing(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql"))

    monkeypatch.setattr(
        "stealthix.detection.sqli.detect_sqli",
        lambda _session, _param=None: [Finding(kind="sqli", target="t")],
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli.detect_nosqli", lambda _session, _param=None: []
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql.detect_newsql", lambda _session, _param=None: []
    )
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda _session, _param=None: [])

    engine = Engine(session)
    result = engine.detect()
    assert result.findings and result.findings[0].kind == "sqli"


def test_engine_all(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))

    monkeypatch.setattr(
        "stealthix.detection.sqli.detect_sqli",
        lambda _session, _param=None: [Finding(kind="sqli", target="t")],
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli.detect_nosqli",
        lambda _session, _param=None: [Finding(kind="nosqli", target="t")],
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql.detect_newsql",
        lambda _session, _param=None: [Finding(kind="newsql", target="t")],
    )
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda _session, _param=None: [])

    engine = Engine(session)
    result = engine.detect()
    assert len(result.findings) == 3
    assert result.metadata["detected_techniques"] == ["union", "boolean", "time"]


def test_engine_normalizes_and_dedupes_duplicate_findings(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql"))

    monkeypatch.setattr(
        "stealthix.detection.sqli.detect_sqli",
        lambda _session, _param=None: [
            Finding(
                kind="sqli-error",
                target="http://example.com/?id=1",
                parameter="id",
                location="query",
                details={
                    "parameter": "id",
                    "location": "query",
                    "payload": "'",
                    "errors": ["sql error"],
                    "signals": ["sql-error-signature"],
                },
            ),
            Finding(
                kind="sqli-error",
                target="http://example.com/?id=2",
                parameter="id",
                location="query",
                details={
                    "parameter": "id",
                    "location": "query",
                    "payload": '"',
                    "errors": ["syntax error"],
                    "signals": ["sql-error-signature"],
                },
            ),
        ],
    )
    monkeypatch.setattr(
        "stealthix.detection.nosqli.detect_nosqli", lambda _session, _param=None: []
    )
    monkeypatch.setattr(
        "stealthix.detection.newsql.detect_newsql", lambda _session, _param=None: []
    )
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda _session, _param=None: [])

    engine = Engine(session)
    result = engine.detect()

    assert len(result.findings) == 1
    details = result.findings[0].details
    assert details["evidence_count"] == 2
    assert set(details["observed_payloads"]) == {"'", '"'}
    assert details["confidence"] in {"high", "confirmed"}


def test_engine_runs_param_tasks_concurrently_and_merges_worker_state(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql", threads=2))
    points = [
        TargetParam(name="id", location="query"),
        TargetParam(name="user", location="query"),
    ]
    barrier = threading.Barrier(len(points))
    thread_ids: list[int] = []
    progress_events: list[dict[str, object]] = []

    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)
    monkeypatch.setattr("stealthix.core.engine.discover_target_params", lambda _session: points)

    def fake_detect_sqli(worker_session, param=None):
        assert param is not None
        worker_session.history.add(f"http://example.com/?{param.name}=1", "GET", "200", 0.01)
        worker_session.metadata.setdefault("tested_params", []).append(
            {"module": "sqli", "name": param.name, "location": param.location}
        )
        thread_ids.append(threading.get_ident())
        barrier.wait(timeout=0.3)
        return [
            Finding(
                kind="sqli-error",
                target=f"http://example.com/?{param.name}=1",
                parameter=param.name,
                location=param.location,
                details={"parameter": param.name, "location": param.location, "payload": "'"},
            )
        ]

    monkeypatch.setattr("stealthix.detection.sqli.detect_sqli", fake_detect_sqli)
    monkeypatch.setattr("stealthix.detection.nosqli.detect_nosqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.newsql.detect_newsql", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda *_args, **_kwargs: [])

    result = Engine(session, progress_callback=progress_events.append).detect()

    assert len(result.findings) == 2
    assert len(set(thread_ids)) == 2
    assert len(session.history) == 2
    assert sorted(item["name"] for item in session.metadata["tested_params"]) == ["id", "user"]
    assert any(event["phase"] == "SQLi Detection" for event in progress_events)


def test_async_engine_supports_fallback_when_no_params_are_discovered(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql", threads=1))

    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)
    monkeypatch.setattr("stealthix.core.engine.discover_target_params", lambda _session: [])
    monkeypatch.setattr(
        "stealthix.detection.sqli.detect_sqli",
        lambda _session, param=None: (
            [
                Finding(
                    kind="sqli",
                    target="http://example.com",
                    details={"parameter": "id", "location": "query", "payload": "1"},
                )
            ]
            if param is None
            else []
        ),
    )
    monkeypatch.setattr("stealthix.detection.nosqli.detect_nosqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.newsql.detect_newsql", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda *_args, **_kwargs: [])

    result = asyncio.run(AsyncEngine(session).detect())

    assert len(result.findings) == 1
    assert result.metadata["injection"] == {"parameter": "id", "location": "query"}


def test_engine_primes_auth_before_detect(monkeypatch):
    session = ScanSession(
        SessionConfig(base_url="http://example.com", auth_type="bearer", auth_token="token-1")
    )
    calls: list[str] = []

    monkeypatch.setattr("stealthix.core.engine.has_auth", lambda _session: True)
    monkeypatch.setattr(
        "stealthix.core.engine.ensure_authenticated",
        lambda _session, reason=None: calls.append(reason or ""),
    )
    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)
    monkeypatch.setattr("stealthix.core.engine.discover_target_params", lambda _session: [])
    monkeypatch.setattr("stealthix.detection.sqli.detect_sqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.nosqli.detect_nosqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.newsql.detect_newsql", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda *_args, **_kwargs: [])

    Engine(session).detect()

    assert calls == ["Authentication"]


def test_engine_detect_resumes_completed_tasks_from_checkpoint(monkeypatch, tmp_path):
    points = [TargetParam(name="id", location="query"), TargetParam(name="user", location="query")]
    session = ScanSession(SessionConfig(base_url="http://example.com", dbms="mysql", threads=1))
    manager = CheckpointManager(tmp_path / "detect.stx", interval_seconds=0)
    calls: list[str] = []

    monkeypatch.setattr("stealthix.plugins.runtime.apply_plugin", lambda _session: None)
    monkeypatch.setattr("stealthix.core.engine.discover_target_params", lambda _session: points)

    def fake_detect(worker_session, param=None):
        assert param is not None
        calls.append(param.name)
        return [
            Finding(
                kind="sqli",
                target=f"http://example.com/?{param.name}=1",
                parameter=param.name,
                location=param.location,
            )
        ]

    monkeypatch.setattr("stealthix.detection.sqli.detect_sqli", fake_detect)
    monkeypatch.setattr("stealthix.detection.nosqli.detect_nosqli", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.newsql.detect_newsql", lambda *_args, **_kwargs: [])
    monkeypatch.setattr("stealthix.detection.common.detect_idor", lambda *_args, **_kwargs: [])

    planner = Engine(session)
    _, _, stages = planner._prepare_runtime()
    completed_task_id = planner._task_key(stages[0], stages[0].tasks[0])
    resume_payload = manager.build_payload(
        session,
        mode="detect",
        status="running",
        state={
            "findings": [
                {
                    "kind": "sqli",
                    "target": "http://example.com/?id=1",
                    "parameter": "id",
                    "location": "query",
                    "details": {},
                }
            ],
            "completed_task_ids": [completed_task_id],
        },
        input_context={"base_url": session.config.base_url},
    )

    resumed_session = ScanSession(
        SessionConfig(base_url="http://example.com", dbms="mysql", threads=1)
    )
    resumed_session.runtime["checkpoint_manager"] = manager
    resumed_session.runtime["checkpoint_resume_payload"] = resume_payload
    resumed_session.runtime["checkpoint_resume_count"] = 1

    result = Engine(resumed_session).detect()

    assert calls == ["user"]
    assert sorted(finding.parameter for finding in result.findings) == ["id", "user"]
    saved = load_checkpoint(tmp_path / "detect.stx")
    assert saved["status"] == "completed"


def test_engine_scan_list_resumes_completed_targets(monkeypatch, tmp_path):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    manager = CheckpointManager(tmp_path / "scan-list.stx", interval_seconds=0)
    specs = [
        "http://example.com/a?id=1",
        "http://example.com/b?id=2",
    ]
    planner = Engine(session)
    first_key = planner._target_spec_key(planner._coerce_target_spec(specs[0]))
    resume_payload = manager.build_payload(
        session,
        mode="scan_list",
        status="running",
        state={
            "findings": [
                {
                    "kind": "sqli",
                    "target": specs[0],
                    "parameter": "id",
                    "location": "query",
                    "details": {},
                }
            ],
            "completed_target_keys": [first_key],
            "per_target_results": [
                {"target": specs[0], "finding_count": 1, "finding_kinds": ["sqli"], "metadata": {}}
            ],
        },
        input_context={"specs": specs},
    )

    calls: list[str] = []

    def fake_detect(self):
        calls.append(self.session.config.base_url)
        return ScanResult(
            target=self.session.config.base_url,
            findings=[Finding(kind="nosqli", target=self.session.config.base_url)],
            metadata={},
        )

    monkeypatch.setattr("stealthix.core.engine.Engine.detect", fake_detect)

    resumed_session = ScanSession(SessionConfig(base_url="http://example.com"))
    resumed_session.runtime["checkpoint_manager"] = manager
    resumed_session.runtime["checkpoint_resume_payload"] = resume_payload
    resumed_session.runtime["checkpoint_resume_count"] = 1

    result = Engine(resumed_session).scan_list(specs)

    assert calls == ["http://example.com/b?id=2"]
    assert len(result.findings) == 2
    saved = load_checkpoint(tmp_path / "scan-list.stx")
    assert saved["status"] == "completed"
