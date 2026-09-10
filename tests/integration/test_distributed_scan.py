"""Integration tests for distributed scanning."""

from __future__ import annotations

import pytest

from stealthix.distributed.models import ScanTask, TaskResult


class TestDistributedScanIntegration:
    """Integration tests for distributed scanning."""

    def test_task_result_roundtrip(self) -> None:
        """Test task result serialization and deserialization roundtrip."""
        original_result = TaskResult(
            task_id="test-task-123",
            findings=[
                {"kind": "sqli-boolean", "target": "http://example.com", "parameter": "id"},
                {"kind": "sqli-time", "target": "http://example.com", "parameter": "search"},
            ],
            metadata={"scan_time": "2024-01-01T00:00:00Z", "worker_count": 4},
            worker_id="worker-1",
        )

        # Serialize
        json_str = original_result.model_dump_json()

        # Deserialize
        deserialized_result = TaskResult.model_validate_json(json_str)

        # Verify
        assert deserialized_result.task_id == original_result.task_id
        assert len(deserialized_result.findings) == len(original_result.findings)
        assert deserialized_result.worker_id == original_result.worker_id
        assert deserialized_result.metadata == original_result.metadata

    def test_scan_task_with_complex_config(self) -> None:
        """Test scan task with complex configuration."""
        task = ScanTask(
            target="http://example.com",
            scan_config={
                "risk": 3,
                "dbms": "mysql",
                "plugins": ["sqli", "nosqli"],
                "auth_type": "bearer",
                "auth_token": "test-token",
                "timeout": 30,
            },
            priority=1,
        )

        assert task.scan_config["risk"] == 3
        assert "sqli" in task.scan_config["plugins"]
        assert task.priority == 1

    def test_multiple_tasks_same_target(self) -> None:
        """Test creating multiple tasks for the same target with different configs."""
        target = "http://example.com"

        task1 = ScanTask(target=target, scan_config={"risk": 1}, priority=0)
        task2 = ScanTask(target=target, scan_config={"risk": 2}, priority=1)
        task3 = ScanTask(target=target, scan_config={"risk": 3}, priority=2)

        assert task1.target == task2.target == task3.target
        assert task1.task_id != task2.task_id != task3.task_id
        assert task1.priority < task2.priority < task3.priority

    def test_task_result_aggregation(self) -> None:
        """Test aggregating results from multiple tasks."""
        results = [
            TaskResult(
                task_id="task-1",
                findings=[{"kind": "sqli", "target": "http://example.com/page1"}],
                metadata={},
                worker_id="worker-1",
            ),
            TaskResult(
                task_id="task-2",
                findings=[{"kind": "nosqli", "target": "http://example.com/page2"}],
                metadata={},
                worker_id="worker-2",
            ),
            TaskResult(
                task_id="task-3",
                findings=[{"kind": "xss", "target": "http://example.com/page3"}],
                metadata={},
                worker_id="worker-1",
            ),
        ]

        # Aggregate findings
        all_findings = []
        for result in results:
            all_findings.extend(result.findings)

        assert len(all_findings) == 3
        assert any(f["kind"] == "sqli" for f in all_findings)
        assert any(f["kind"] == "nosqli" for f in all_findings)
        assert any(f["kind"] == "xss" for f in all_findings)
