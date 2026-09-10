"""Unit tests for distributed task queue."""

from __future__ import annotations

import threading
from typing import Any

import pytest

from stealthix.core.models import ScanResult
from stealthix.distributed.models import ScanTask, TaskArtifact, TaskResult, WorkerCapabilities
from stealthix.distributed.queue import (
    TASK_DEAD_LETTER_KEY,
    TASK_LEASE_KEY,
    TASK_QUEUE_KEY,
    TASK_RESULT_KEY,
    TASK_SCAN_KEY,
    TASK_STATUS_KEY,
    WORKER_HEARTBEAT_KEY,
    RedisTaskQueue,
)


class FakeRedis:
    def __init__(self) -> None:
        self.values: dict[str, Any] = {}
        self.hashes: dict[str, dict[str, Any]] = {}
        self.sorted_sets: dict[str, dict[str, float]] = {}
        self.lock = threading.Lock()

    def ping(self) -> bool:
        return True

    def close(self) -> None:
        return None

    def set(self, key: str, value: Any, ex: int | None = None) -> None:
        self.values[key] = value

    def get(self, key: str) -> Any:
        return self.values.get(key)

    def delete(self, *keys: str) -> int:
        deleted = 0
        for key in keys:
            deleted += int(key in self.values or key in self.hashes or key in self.sorted_sets)
            self.values.pop(key, None)
            self.hashes.pop(key, None)
            self.sorted_sets.pop(key, None)
        return deleted

    def keys(self, pattern: str) -> list[str]:
        if not pattern.endswith("*"):
            return [pattern] if pattern in self.values else []
        prefix = pattern[:-1]
        return [key for key in self.values if key.startswith(prefix)]

    def hset(self, key: str, field: str, value: Any) -> None:
        self.hashes.setdefault(key, {})[field] = value

    def hget(self, key: str, field: str) -> Any:
        return self.hashes.get(key, {}).get(field)

    def hdel(self, key: str, field: str) -> None:
        self.hashes.get(key, {}).pop(field, None)

    def hincrby(self, key: str, field: str, amount: int) -> int:
        current = int(self.hashes.setdefault(key, {}).get(field, 0))
        updated = current + amount
        self.hashes[key][field] = updated
        return updated

    def zadd(self, key: str, mapping: dict[str, float]) -> None:
        zset = self.sorted_sets.setdefault(key, {})
        for member, score in mapping.items():
            zset[member] = float(score)

    def zpopmin(self, key: str, count: int = 1) -> list[tuple[str, float]]:
        zset = self.sorted_sets.setdefault(key, {})
        members = sorted(zset.items(), key=lambda item: (item[1], item[0]))[:count]
        for member, _score in members:
            zset.pop(member, None)
        return members

    def zcard(self, key: str) -> int:
        return len(self.sorted_sets.get(key, {}))

    def zrem(self, key: str, member: str) -> None:
        self.sorted_sets.get(key, {}).pop(member, None)

    def zrangebyscore(self, key: str, min: float, max: float) -> list[str]:
        return [
            member
            for member, score in sorted(
                self.sorted_sets.get(key, {}).items(), key=lambda item: item[1]
            )
            if float(min) <= score <= float(max)
        ]

    def zrange(self, key: str, start: int, end: int) -> list[str]:
        members = [
            member
            for member, _score in sorted(
                self.sorted_sets.get(key, {}).items(), key=lambda item: item[1]
            )
        ]
        if end == -1:
            return members[start:]
        return members[start : end + 1]

    def eval(self, script: str, numkeys: int, *keys_and_args: Any) -> list[Any] | None:
        del script
        keys = list(keys_and_args[:numkeys])
        args = list(keys_and_args[numkeys:])
        (
            queue_key,
            payload_key,
            attempts_key,
            lease_key,
            lease_worker_key,
            status_prefix,
            scan_key,
            cancelled_prefix,
        ) = keys
        worker_id, lease_expires_at = args

        with self.lock:
            while True:
                queued = self.zrange(queue_key, 0, 0)
                if not queued:
                    return None

                task_id = queued[0]
                payload = self.hget(payload_key, task_id)
                self.zrem(queue_key, task_id)

                if not payload:
                    continue

                scan_id = self.hget(scan_key, task_id)
                if scan_id and self.get(f"{cancelled_prefix}{scan_id}") is not None:
                    self.set(f"{status_prefix}{task_id}", "cancelled")
                    continue

                attempts = self.hincrby(attempts_key, task_id, 1)
                self.zadd(lease_key, {task_id: float(lease_expires_at)})
                self.hset(lease_worker_key, task_id, worker_id)
                self.set(f"{status_prefix}{task_id}", "running")
                self.set(f"{status_prefix}{task_id}:worker", worker_id)
                return [task_id, payload, str(attempts)]


def queue_with_fake_redis(
    *, lease_ttl: int = 300, max_retries: int = 3
) -> tuple[RedisTaskQueue, FakeRedis]:
    queue = RedisTaskQueue(lease_ttl=lease_ttl, max_retries=max_retries)
    fake = FakeRedis()
    queue._redis = fake  # noqa: SLF001 - tests inject a Redis double
    return queue, fake


class TestScanTask:
    """Test ScanTask model."""

    def test_create_task(self) -> None:
        """Test creating a scan task."""
        task = ScanTask(
            target="http://example.com",
            scan_config={"risk": 2},
            priority=0,
        )
        assert task.target == "http://example.com"
        assert task.scan_config == {"risk": 2}
        assert task.priority == 0
        assert task.status == "pending"
        assert task.task_id is not None

    def test_task_serialization(self) -> None:
        """Test task JSON serialization."""
        task = ScanTask(
            target="http://example.com",
            scan_config={"risk": 2},
            priority=1,
        )
        json_str = task.model_dump_json()
        assert "http://example.com" in json_str
        assert "risk" in json_str

    def test_task_deserialization(self) -> None:
        """Test task JSON deserialization."""
        json_str = '{"task_id":"test-id","target":"http://example.com","scan_config":{"risk":2},"priority":0,"status":"pending","created_at":"2024-01-01T00:00:00Z"}'
        task = ScanTask.model_validate_json(json_str)
        assert task.target == "http://example.com"
        assert task.task_id == "test-id"


class TestTaskResult:
    """Test TaskResult model."""

    def test_create_result(self) -> None:
        """Test creating a task result."""
        result = TaskResult(
            task_id="test-task",
            findings=[{"kind": "sqli", "target": "http://example.com"}],
            metadata={"test": "data"},
            worker_id="worker-1",
        )
        assert result.task_id == "test-task"
        assert len(result.findings) == 1
        assert result.worker_id == "worker-1"
        assert result.error is None

    def test_result_with_error(self) -> None:
        """Test creating a task result with error."""
        result = TaskResult(
            task_id="test-task",
            findings=[],
            metadata={},
            worker_id="worker-1",
            error="Connection failed",
        )
        assert result.error == "Connection failed"

    def test_result_serialization(self) -> None:
        """Test result JSON serialization."""
        result = TaskResult(
            task_id="test-task",
            findings=[{"kind": "sqli"}],
            metadata={},
            worker_id="worker-1",
        )
        json_str = result.model_dump_json()
        assert "test-task" in json_str
        assert "worker-1" in json_str

    def test_result_with_artifacts_and_capabilities(self) -> None:
        result = TaskResult(
            task_id="test-task",
            findings=[],
            metadata={},
            worker_id="worker-1",
            artifacts=[
                TaskArtifact(
                    kind="evidence",
                    uri="file:///tmp/evidence.json",
                    media_type="application/json",
                    sha256="a" * 64,
                    size_bytes=42,
                )
            ],
            worker_capabilities=WorkerCapabilities(
                worker_id="worker-1",
                platform="test",
                python="3.12",
                rust_core=True,
                detectors=["sqli"],
            ),
        )

        restored = TaskResult.model_validate_json(result.model_dump_json())

        assert restored.artifacts[0].kind == "evidence"
        assert restored.worker_capabilities is not None
        assert restored.worker_capabilities.rust_core is True

    def test_result_deserialization(self) -> None:
        """Test result JSON deserialization."""
        json_str = '{"task_id":"test-task","findings":[],"metadata":{},"worker_id":"worker-1","error":null,"completed_at":"2024-01-01T00:00:00Z"}'
        result = TaskResult.model_validate_json(json_str)
        assert result.task_id == "test-task"
        assert result.worker_id == "worker-1"


class TestRedisTaskQueueSemantics:
    def test_dequeue_leases_task_and_ack_removes_lease(self) -> None:
        queue, fake = queue_with_fake_redis()
        task = ScanTask(task_id="task-1", target="http://example.com", scan_config={}, priority=0)

        queue.enqueue_task(task)
        dequeued = queue.dequeue_task("worker-1", timeout=0)

        assert dequeued is not None
        assert dequeued.task_id == "task-1"
        assert queue.get_queue_size() == 0
        assert "task-1" in fake.sorted_sets[TASK_LEASE_KEY]
        assert queue.get_task_status("task-1") == "running"

        result = TaskResult(task_id="task-1", findings=[], metadata={}, worker_id="worker-1")
        queue.mark_task_complete("task-1", result)

        assert "task-1" not in fake.sorted_sets.get(TASK_LEASE_KEY, {})
        assert queue.get_task_status("task-1") == "completed"
        assert queue.get_task_result("task-1") == result

    def test_expired_lease_is_requeued_for_another_worker(self) -> None:
        queue, fake = queue_with_fake_redis(lease_ttl=1, max_retries=3)
        task = ScanTask(task_id="task-1", target="http://example.com", scan_config={}, priority=0)

        queue.enqueue_task(task)
        assert queue.dequeue_task("worker-1", timeout=0) is not None
        fake.sorted_sets[TASK_LEASE_KEY]["task-1"] = 0

        assert queue.requeue_expired_leases() == 1
        assert queue.get_task_status("task-1") == "pending"
        assert "task-1" in fake.sorted_sets[TASK_QUEUE_KEY]

        dequeued = queue.dequeue_task("worker-2", timeout=0)
        assert dequeued is not None
        assert dequeued.task_id == "task-1"

    def test_expired_lease_dead_letters_after_retry_budget(self) -> None:
        queue, fake = queue_with_fake_redis(lease_ttl=1, max_retries=1)
        task = ScanTask(task_id="task-1", target="http://example.com", scan_config={}, priority=0)

        queue.enqueue_task(task)
        assert queue.dequeue_task("worker-1", timeout=0) is not None
        fake.sorted_sets[TASK_LEASE_KEY]["task-1"] = 0

        assert queue.requeue_expired_leases() == 1

        assert queue.get_task_status("task-1") == "dead-lettered"
        assert "task-1" in fake.sorted_sets[TASK_DEAD_LETTER_KEY]
        assert queue.get_dead_lettered_tasks()[0].task_id == "task-1"
        assert queue.get_queue_size() == 0

    def test_failed_task_requeues_until_dead_letter_threshold(self) -> None:
        queue, fake = queue_with_fake_redis(max_retries=2)
        task = ScanTask(task_id="task-1", target="http://example.com", scan_config={}, priority=0)

        queue.enqueue_task(task)
        assert queue.dequeue_task("worker-1", timeout=0) is not None
        queue.mark_task_failed("task-1", "temporary")

        assert queue.get_task_status("task-1") == "pending"
        assert "task-1" in fake.sorted_sets[TASK_QUEUE_KEY]

        assert queue.dequeue_task("worker-2", timeout=0) is not None
        queue.mark_task_failed("task-1", "still failing")

        assert queue.get_task_status("task-1") == "dead-lettered"
        assert fake.values[f"{TASK_RESULT_KEY}task-1:error"] == "still failing"
        assert "task-1" in fake.sorted_sets[TASK_DEAD_LETTER_KEY]

    def test_get_active_workers_honors_timeout_argument(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        queue, fake = queue_with_fake_redis()
        monkeypatch.setattr("stealthix.distributed.queue.time.time", lambda: 100.0)
        fake.set(f"{WORKER_HEARTBEAT_KEY}fresh", "95")
        fake.set(f"{WORKER_HEARTBEAT_KEY}stale", "80")

        assert queue.get_active_workers(timeout=10) == ["fresh"]
        assert sorted(queue.get_active_workers(timeout=25)) == ["fresh", "stale"]

    def test_concurrent_workers_atomically_claim_distinct_tasks(self) -> None:
        queue, _fake = queue_with_fake_redis()
        task_ids = [f"task-{index}" for index in range(20)]
        for task_id in task_ids:
            queue.enqueue_task(
                ScanTask(task_id=task_id, target=f"http://example.com/{task_id}", scan_config={})
            )

        claimed: list[str] = []
        claimed_lock = threading.Lock()

        def worker(worker_id: str) -> None:
            while True:
                task = queue.dequeue_task(worker_id, timeout=0)
                if task is None:
                    return
                with claimed_lock:
                    claimed.append(task.task_id)

        threads = [threading.Thread(target=worker, args=(f"worker-{index}",)) for index in range(5)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        assert sorted(claimed) == sorted(task_ids)
        assert len(claimed) == len(set(claimed))
        assert queue.get_queue_size() == 0

    def test_cancelled_scan_tasks_are_not_dequeued_as_new_work(self) -> None:
        queue, fake = queue_with_fake_redis()
        cancelled = ScanTask(
            task_id="task-cancelled",
            scan_id="scan-cancelled",
            target="http://example.com/cancelled",
            scan_config={},
        )
        active = ScanTask(
            task_id="task-active",
            scan_id="scan-active",
            target="http://example.com/active",
            scan_config={},
        )

        queue.enqueue_task(cancelled)
        queue.enqueue_task(active)
        queue.cancel_scan("scan-cancelled")

        dequeued = queue.dequeue_task("worker-1", timeout=0)

        assert dequeued is not None
        assert dequeued.task_id == "task-active"
        assert queue.get_task_status("task-cancelled") == "cancelled"
        assert "task-cancelled" not in fake.sorted_sets.get(TASK_QUEUE_KEY, {})
        assert "task-cancelled" not in fake.sorted_sets.get(TASK_LEASE_KEY, {})
        assert fake.hashes[TASK_SCAN_KEY]["task-cancelled"] == "scan-cancelled"


def test_worker_progress_callback_accepts_engine_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    from stealthix.distributed import worker as worker_module

    progress_updates: list[float] = []

    class FakeQueue:
        def is_scan_cancelled(self, scan_id: str | None) -> bool:
            return False

        def update_task_progress(self, task_id: str, progress: float) -> None:
            assert task_id == "task-1"
            progress_updates.append(progress)

    class FakeEngine:
        def __init__(
            self, *, progress_callback: Any, distributed_mode: bool, task_id: str, **_: Any
        ) -> None:
            assert distributed_mode is True
            assert task_id == "task-1"
            self.progress_callback = progress_callback

        def detect(self) -> ScanResult:
            self.progress_callback(
                {
                    "phase": "SQLi Detection",
                    "message": "Testing parameters",
                    "progress_percent": 42,
                }
            )
            return ScanResult(target="http://example.com", findings=[], metadata={})

    monkeypatch.setattr(worker_module, "Engine", FakeEngine)
    worker = worker_module.DistributedWorker(worker_id="worker-1")
    worker.queue = FakeQueue()  # type: ignore[assignment]
    task = ScanTask(task_id="task-1", target="http://example.com", scan_config={})

    result = worker._execute_task(task)  # noqa: SLF001 - focused callback contract test

    assert progress_updates == [0.0, 0.42]
    assert result.task_id == "task-1"
    assert result.worker_id == "worker-1"


def test_coordinator_treats_dead_lettered_tasks_as_terminal_failures() -> None:
    from stealthix.distributed.coordinator import ScanCoordinator

    class FakeQueue:
        def connect(self) -> None:
            return None

        def get_task_status(self, task_id: str) -> str:
            return {"task-1": "completed", "task-2": "dead-lettered"}[task_id]

    coordinator = ScanCoordinator()
    coordinator.queue = FakeQueue()  # type: ignore[assignment]
    coordinator._task_ids = ["task-1", "task-2"]  # noqa: SLF001 - progress accounting test

    progress = coordinator.get_scan_progress()

    assert progress["completed_tasks"] == 1
    assert progress["failed_tasks"] == 1
    assert progress["pending_tasks"] == 0
