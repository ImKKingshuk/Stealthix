"""Scan coordinator for distributed task distribution."""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from stealthix.core.models import Finding, ScanResult
from stealthix.distributed.models import ScanTask, TaskResult
from stealthix.distributed.queue import RedisTaskQueue

logger = logging.getLogger(__name__)


class ScanCoordinator:
    """Coordinates distributed scan execution across multiple workers."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: str | None = None,
        chunk_size: int = 25,
    ) -> None:
        """Initialize scan coordinator.

        Args:
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
            redis_password: Redis password
            chunk_size: Number of targets per task chunk
        """
        self.scan_id = str(uuid.uuid4())
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.redis_password = redis_password
        self.chunk_size = chunk_size
        self.queue = RedisTaskQueue(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
        )
        self._task_ids: list[str] = []

    def distribute_scan(
        self,
        targets: list[str],
        scan_config: dict[str, Any],
    ) -> str:
        """Distribute scan tasks across workers.

        Args:
            targets: List of target URLs to scan
            scan_config: Scan configuration dictionary

        Returns:
            Scan ID
        """
        logger.info(
            f"Distributing {len(targets)} targets across workers (chunk size: {self.chunk_size})"
        )
        self.queue.connect()

        # Split targets into chunks
        target_chunks = [
            targets[i : i + self.chunk_size] for i in range(0, len(targets), self.chunk_size)
        ]

        # Create and enqueue tasks
        for chunk in target_chunks:
            for target in chunk:
                task = ScanTask(
                    scan_id=self.scan_id,
                    target=target,
                    scan_config=scan_config,
                    priority=0,
                )
                task_id = self.queue.enqueue_task(task)
                self._task_ids.append(task_id)

        logger.info(f"Enqueued {len(self._task_ids)} tasks for scan {self.scan_id}")
        return self.scan_id

    def get_scan_progress(self) -> dict[str, Any]:
        """Get overall scan progress.

        Returns:
            Dictionary with progress information
        """
        self.queue.connect()
        total_tasks = len(self._task_ids)
        completed_tasks = 0
        failed_tasks = 0
        running_tasks = 0
        pending_tasks = 0

        for task_id in self._task_ids:
            status = self.queue.get_task_status(task_id)
            if status == "completed":
                completed_tasks += 1
            elif status in {"failed", "dead-lettered", "cancelled"}:
                failed_tasks += 1
            elif status == "running":
                running_tasks += 1
            else:
                pending_tasks += 1

        progress = completed_tasks / total_tasks if total_tasks > 0 else 0.0

        return {
            "scan_id": self.scan_id,
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "failed_tasks": failed_tasks,
            "running_tasks": running_tasks,
            "pending_tasks": pending_tasks,
            "progress": progress,
        }

    def wait_for_completion(
        self, poll_interval: float = 1.0, timeout: float | None = None
    ) -> ScanResult:
        """Wait for all tasks to complete and aggregate results.

        Args:
            poll_interval: Polling interval in seconds
            timeout: Maximum time to wait in seconds

        Returns:
            Aggregated ScanResult
        """
        logger.info(f"Waiting for scan {self.scan_id} to complete")
        self.queue.connect()

        start_time = time.time()
        all_findings: list[Finding] = []
        all_metadata: dict[str, Any] = {}
        artifacts: list[dict[str, Any]] = []
        worker_capabilities: dict[str, dict[str, Any]] = {}

        while True:
            progress = self.get_scan_progress()
            logger.info(
                f"Scan progress: {progress['progress']:.1%} "
                f"({progress['completed_tasks']}/{progress['total_tasks']} completed)"
            )

            if progress["completed_tasks"] + progress["failed_tasks"] == progress["total_tasks"]:
                break

            if timeout and (time.time() - start_time) > timeout:
                raise TimeoutError(f"Scan timeout after {timeout} seconds")

            time.sleep(poll_interval)

        # Aggregate results
        for task_id in self._task_ids:
            task_result = self.queue.get_task_result(task_id)
            if task_result:
                # Convert findings back to Finding objects
                for finding_data in task_result.findings:
                    try:
                        finding = Finding(**finding_data)
                        all_findings.append(finding)
                    except Exception as e:
                        logger.error(f"Error deserializing finding: {e}")
                all_metadata.update(task_result.metadata)
                artifacts.extend(
                    artifact.model_dump(mode="json") for artifact in task_result.artifacts
                )
                if task_result.worker_capabilities:
                    worker_capabilities[task_result.worker_id] = (
                        task_result.worker_capabilities.model_dump(mode="json")
                    )

        # Create aggregated ScanResult
        # Use the first target as the primary target for the result
        first_task = self.queue.get_task_result(self._task_ids[0])
        primary_target = (
            first_task.findings[0].get("target")
            if first_task and first_task.findings
            else "unknown"
        )
        if primary_target is None or primary_target == "unknown":
            primary_target = str(primary_target) if primary_target else "unknown"

        result = ScanResult(
            target=primary_target,
            findings=all_findings,
            metadata={
                **all_metadata,
                "distributed": {
                    "scan_id": self.scan_id,
                    "task_ids": list(self._task_ids),
                    "artifacts": artifacts,
                    "worker_capabilities": worker_capabilities,
                },
            },
        )

        logger.info(f"Scan {self.scan_id} completed with {len(all_findings)} findings")
        return result

    def cancel_scan(self) -> None:
        """Cancel the distributed scan."""
        logger.info(f"Cancelling scan {self.scan_id}")
        self.queue.connect()
        self.queue.cancel_scan(self.scan_id, self._task_ids)

    def get_active_workers(self, timeout: int = 60) -> list[str]:
        """Get list of active workers.

        Args:
            timeout: Worker timeout in seconds

        Returns:
            List of active worker IDs
        """
        self.queue.connect()
        return self.queue.get_active_workers(timeout=timeout)


__all__ = ["ScanCoordinator"]
