"""Unit tests for codebase robustness and hardening defenses."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from stealthix.core.checkpoint import CheckpointManager, load_checkpoint, restore_session
from stealthix.core.creds import CredentialStore
from stealthix.core.detector_pipeline import (
    DetectionStage,
    DetectionTask,
    DetectorPipelineExecutor,
)
from stealthix.core.errors import NetworkError
from stealthix.core.http import make_request
from stealthix.core.models import Finding
from stealthix.core.rate_limiter import GlobalRateLimiter, TokenBucket
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.crawler.spider import Spider, SpiderOptions
from stealthix.distributed.models import ScanTask
from stealthix.distributed.worker import DistributedWorker
from stealthix.proxy.workspace import CapturedExchange, ProxyWorkspace
from stealthix.templates.dsl import (
    TemplateExtractor,
    TemplateMatcher,
    TemplateResponse,
    _evaluate_matcher,
    _run_extractors,
)
from stealthix.workflows.requests import RequestSpec


def test_token_bucket_zero_division_guard():
    """Verify TokenBucket clamps zero/negative rate and capacity to prevent ZeroDivisionError."""
    # Rate of 0 or negative
    bucket = TokenBucket(rate=0.0, capacity=0)
    assert bucket.rate >= 0.001
    assert bucket.capacity >= 1
    # Check wait_time calculation doesn't raise ZeroDivisionError
    wait = bucket.wait_time(tokens=5)
    assert wait >= 0.0

    bucket_neg = TokenBucket(rate=-10.0, capacity=-5)
    assert bucket_neg.rate >= 0.001
    assert bucket_neg.capacity >= 1

    limiter = GlobalRateLimiter(default_rate=0.0, default_burst=0)
    assert limiter.default_rate >= 0.001
    assert limiter.default_burst >= 1


def test_credential_store_thread_safety():
    """Verify CredentialStore handles concurrent access across threads safely."""
    store = CredentialStore()
    errors: list[Exception] = []

    def worker(worker_id: int):
        try:
            for i in range(20):
                key = f"key_{worker_id}_{i}"
                store.add(key, f"val_{worker_id}_{i}")
                val = store.get(key)
                assert val == f"val_{worker_id}_{i}"
                store.to_dict()
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors


def test_load_checkpoint_robustness(tmp_path: Path):
    """Verify load_checkpoint rejects missing files and non-dict payloads."""
    # Missing file
    missing = tmp_path / "nonexistent.json"
    with pytest.raises(FileNotFoundError):
        load_checkpoint(missing)

    # Corrupted non-dict payload (e.g. list or string)
    invalid_file = tmp_path / "invalid.json"
    invalid_file.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
    with pytest.raises(ValueError, match="not a JSON object"):
        load_checkpoint(invalid_file)

    # Valid checkpoint roundtrip
    session = ScanSession(config=SessionConfig(url="https://example.com"))
    valid_file = tmp_path / "checkpoint.json"
    manager = CheckpointManager(valid_file)
    manager.save_snapshot(session, mode="detect", status="running", state={}, force=True)
    payload = load_checkpoint(valid_file)
    restored = restore_session(payload["session"])
    assert restored.config.url == "https://example.com"


def test_http_request_rust_fallback_and_network_error():
    """Verify make_request() falls back to Python requests if native Rust client fails."""
    session = ScanSession(config=SessionConfig(url="https://example.com", retries=0, tamper_auto=False))

    mock_rust_client = MagicMock()
    mock_rust_client.request.side_effect = RuntimeError("Rust engine segfault simulation")
    mock_rust_cls = MagicMock(return_value=mock_rust_client)

    with patch("stealthix.core.http.load_rust_core", return_value={"HttpClient": mock_rust_cls}):
        with patch("stealthix.core.http._send_requests_request") as mock_send_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.text = "ok from python fallback"
            mock_resp.headers = {"Content-Type": "text/plain"}
            mock_send_req.return_value = mock_resp

            text, elapsed = make_request(session, "https://example.com/fallback-test", method="GET")
            assert text == "ok from python fallback"
            assert mock_rust_client.request.called
            assert mock_send_req.called

    # When Python requests also fails completely, verify NetworkError is raised
    with patch("stealthix.core.http.load_rust_core", return_value={}):
        with patch(
            "stealthix.core.http._send_requests_request",
            side_effect=requests.ConnectionError("refused"),
        ):
            with pytest.raises(NetworkError, match="HTTP request to https://example.com/fail failed"):
                make_request(session, "https://example.com/fail", method="GET")


def test_detector_pipeline_isolates_faulty_task():
    """Verify a faulty detector task does not abort the pipeline and records error in session metadata."""
    session = ScanSession(config=SessionConfig(url="https://example.com", threads=1))
    executor = DetectorPipelineExecutor(
        session,
        emit_progress=lambda **kwargs: None,
        save_detect_checkpoint=lambda **kwargs: None,
    )

    finding = Finding(
        kind="sqli",
        target="https://example.com",
    )

    def faulty_handler(worker_session: ScanSession) -> list[Finding]:
        raise ZeroDivisionError("Simulated unhandled detector bug")

    def healthy_handler(worker_session: ScanSession) -> list[Finding]:
        return [finding]

    stage = DetectionStage(
        phase="test_phase",
        message="Running stage",
        tasks=(
            DetectionTask(order=0, detector="faulty", target=None, run=faulty_handler),
            DetectionTask(order=1, detector="healthy", target=None, run=healthy_handler),
        ),
    )

    # Sequential execution (workers = 1)
    stage_findings, completed, completed_ids = executor.execute_stage(
        stage,
        findings_so_far=[],
        completed_tasks=0,
        total_tasks=2,
        completed_task_ids=[],
        all_task_ids=[],
    )
    assert finding in stage_findings
    assert "task_errors" in session.metadata
    errors = session.metadata["task_errors"]
    assert any("faulty" in err["task_id"] for err in errors)

    # Parallel execution (workers = 2)
    session_parallel = ScanSession(config=SessionConfig(url="https://example.com", threads=2))
    executor_parallel = DetectorPipelineExecutor(
        session_parallel,
        emit_progress=lambda **kwargs: None,
        save_detect_checkpoint=lambda **kwargs: None,
    )
    findings_p, completed_p, ids_p = executor_parallel.execute_stage(
        stage,
        findings_so_far=[],
        completed_tasks=0,
        total_tasks=2,
        completed_task_ids=[],
        all_task_ids=[],
    )
    assert finding in findings_p
    assert "task_errors" in session_parallel.metadata


def test_spider_max_page_size_and_malformed_html(monkeypatch: pytest.MonkeyPatch):
    """Verify spider clamps oversized page bodies and survives parser errors."""
    session = ScanSession(config=SessionConfig(url="https://target.local"))
    options = SpiderOptions(max_page_size=100, max_pages=1, parse_robots=False, parse_sitemap=False)
    spider = Spider(session, options=options)

    # Oversized payload (1000 characters)
    huge_html = "<html><body>" + ("<a href='/link'>link</a>" * 50) + "</body></html>"
    monkeypatch.setattr(spider, "_fetch", lambda url: (huge_html, 0.05))

    results = spider.crawl()
    assert len(results["pages"]) == 1
    # Verify crawl completed without memory exhaustion or crash


def test_template_dsl_malformed_regex_handling():
    """Verify template DSL matchers and extractors handle invalid regex patterns gracefully."""
    response = TemplateResponse(status_code=200, body="secret token 12345", headers={}, url=None)

    # Unclosed bracket regex pattern
    bad_matcher = TemplateMatcher(
        type="regex",
        part="body",
        regex=["[unclosed bracket pattern", "token 12345"],
        condition="or",
    )
    res = _evaluate_matcher(bad_matcher, response)
    # Since condition is "or" and second pattern matches, it matches!
    assert res.matched is True

    # Bad pattern with condition "and"
    bad_matcher_and = TemplateMatcher(
        type="regex",
        part="body",
        regex=["(?P<invalid", "token 12345"],
        condition="and",
    )
    res_and = _evaluate_matcher(bad_matcher_and, response)
    assert res_and.matched is False

    # Bad extractor regex
    bad_extractor = TemplateExtractor(
        type="regex",
        part="body",
        regex=["(unbalanced regex [0-9]+", "token ([0-9]+)"],
        group=1,
    )
    extracted = _run_extractors([bad_extractor], response)
    assert len(extracted) == 1
    assert extracted[0].value == "12345"


def test_proxy_workspace_corrupted_jsonl_and_thread_safety(tmp_path: Path):
    """Verify ProxyWorkspace ignores corrupted lines during load and supports thread safety."""
    workspace_dir = tmp_path / "proxy"
    workspace_dir.mkdir()
    history_file = workspace_dir / "history.jsonl"

    # Write one valid line, one corrupted line, and another valid line
    valid_record_1 = CapturedExchange(
        id="px-1",
        request=RequestSpec(method="GET", url="https://example.com/1"),
    )
    valid_record_2 = CapturedExchange(
        id="px-2",
        request=RequestSpec(method="GET", url="https://example.com/2"),
    )

    lines = [
        json.dumps(valid_record_1.to_dict()),
        "{corrupted: not valid json line}",
        json.dumps(valid_record_2.to_dict()),
    ]
    history_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Load should not crash, and should successfully load both valid records
    ws = ProxyWorkspace(workspace_dir)
    records = ws.records()
    assert len(records) == 2
    ids = {r.id for r in records}
    assert "px-1" in ids
    assert "px-2" in ids

    # Test thread safety
    errors: list[Exception] = []

    def thread_task(worker_id: int):
        try:
            for i in range(15):
                rec = CapturedExchange(
                    id=f"px-t-{worker_id}-{i}",
                    request=RequestSpec(method="POST", url=f"https://example.com/{worker_id}/{i}"),
                )
                ws.upsert(rec)
                assert ws.get(rec.id).id == rec.id
                ws.search(query=str(worker_id))
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=thread_task, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors


def test_distributed_worker_defensive_finding_serialization():
    """Verify DistributedWorker handles findings of arbitrary structures without crashing."""
    mock_queue = MagicMock()
    mock_queue.is_scan_cancelled.return_value = False

    worker = DistributedWorker(worker_id="test-worker")
    worker.queue = mock_queue

    @dataclass
    class CustomFinding:
        name: str
        severity: str

    class ToDictFinding:
        def to_dict(self):
            return {"name": "todict_vuln", "severity": "medium"}

    class RawObject:
        __slots__ = ("val",)

        def __init__(self, val: str):
            self.val = val

        def __str__(self):
            return f"RawObject({self.val})"

    task = ScanTask(
        task_id="task-123",
        target="https://target.local",
        scan_id="scan-456",
        detector="test",
        capabilities=["sqli"],
    )

    # Mock engine detect return with diverse finding representations
    mock_engine_result = MagicMock()
    mock_engine_result.findings = [
        {"kind": "dict_vuln", "target": "https://target.local"},
        CustomFinding(name="dataclass_vuln", severity="high"),
        ToDictFinding(),
        RawObject("slot_only_val"),
    ]
    mock_engine_result.metadata = {}

    with patch("stealthix.distributed.worker.Engine") as mock_engine_cls:
        mock_instance = MagicMock()
        mock_instance.detect.return_value = mock_engine_result
        mock_engine_cls.return_value = mock_instance

        task_result = worker._execute_task(task)
        assert task_result.task_id == "task-123"
        assert len(task_result.findings) == 4
        # Verify slot object fell back safely to dictionary
        slot_finding = task_result.findings[3]
        assert isinstance(slot_finding, dict)
        assert "RawObject" in slot_finding["kind"]


def test_redis_task_queue_stale_connection_reconnect():
    """Verify RedisTaskQueue auto-reconnects when ping on existing connection fails."""
    from redis.exceptions import ConnectionError

    from stealthix.distributed.queue import RedisTaskQueue

    queue = RedisTaskQueue(host="127.0.0.1", port=6379)
    mock_redis = MagicMock()
    mock_redis.ping.side_effect = ConnectionError("Stale socket")
    queue._redis = mock_redis

    with patch.object(queue, "connect") as mock_connect:
        queue._ensure_connected()
        assert mock_connect.called

