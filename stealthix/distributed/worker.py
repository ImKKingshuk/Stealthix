"""Distributed worker process for Stealthix."""

from __future__ import annotations

import logging
import platform
import signal
import sys
import threading
import time
import uuid
from typing import Any

from stealthix.core.engine import Engine
from stealthix.core.models import ScanResult
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.distributed.models import ScanTask, TaskResult, WorkerCapabilities
from stealthix.distributed.queue import RedisTaskQueue

logger = logging.getLogger(__name__)


class DistributedWorker:
    """Distributed worker process for executing scan tasks."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 0,
        redis_password: str | None = None,
        worker_id: str | None = None,
    ) -> None:
        """Initialize distributed worker.

        Args:
            redis_host: Redis host
            redis_port: Redis port
            redis_db: Redis database number
            redis_password: Redis password
            worker_id: Worker ID (auto-generated if not provided)
        """
        self.worker_id = worker_id or str(uuid.uuid4())
        self.redis_host = redis_host
        self.redis_port = redis_port
        self.redis_db = redis_db
        self.redis_password = redis_password
        self.queue = RedisTaskQueue(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            password=redis_password,
        )
        self._running = False
        self._shutdown_event = threading.Event()
        self.capabilities = self._build_capabilities()

    def _build_capabilities(self) -> WorkerCapabilities:
        """Return static capability metadata for scheduler/aggregator decisions."""
        try:
            from stealthix.utils import load_rust_core

            rust_core = bool(load_rust_core())
        except Exception:
            rust_core = False
        return WorkerCapabilities(
            worker_id=self.worker_id,
            platform=platform.platform(),
            python=platform.python_version(),
            rust_core=rust_core,
            detectors=[
                "sqli",
                "nosqli",
                "newsql",
                "graphql",
                "graphqli",
                "searchqli",
                "timeseriesqli",
                "websocket",
            ],
        )

    def run(self) -> None:
        """Run worker main loop."""
        logger.info(f"Starting worker {self.worker_id}")
        self._running = True

        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)

        try:
            self.queue.connect()
            self.queue.update_worker_heartbeat(self.worker_id)

            while self._running and not self._shutdown_event.is_set():
                # Update heartbeat
                self.queue.update_worker_heartbeat(self.worker_id)

                # Dequeue task
                task = self.queue.dequeue_task(self.worker_id, timeout=5)
                if task:
                    logger.info(f"Worker {self.worker_id} processing task {task.task_id}")
                    try:
                        if self.queue.is_scan_cancelled(task.scan_id):
                            self.queue.mark_task_cancelled(task.task_id)
                            continue
                        result = self._execute_task(task)
                        if self.queue.is_scan_cancelled(task.scan_id):
                            self.queue.mark_task_cancelled(task.task_id)
                        else:
                            self.queue.mark_task_complete(task.task_id, result)
                    except Exception as e:
                        logger.error(f"Error executing task {task.task_id}: {e}", exc_info=True)
                        if self.queue.is_scan_cancelled(task.scan_id):
                            self.queue.mark_task_cancelled(task.task_id)
                        else:
                            self.queue.mark_task_failed(task.task_id, str(e))

        except KeyboardInterrupt:
            logger.info("Worker interrupted by keyboard")
        except Exception as e:
            logger.error(f"Worker error: {e}", exc_info=True)
        finally:
            self.stop()

    def _execute_task(self, task: ScanTask) -> TaskResult:
        """Execute a scan task.

        Args:
            task: ScanTask to execute

        Returns:
            TaskResult
        """
        # Update progress
        self.queue.update_task_progress(task.task_id, 0.0)

        # Create engine with task config
        config = task.scan_config.copy()
        config.setdefault("base_url", task.target)
        config["distributed_mode"] = True
        config["task_id"] = task.task_id

        # Create session and progress callback for distributed mode
        session_config = SessionConfig(**config)
        session = ScanSession(config=session_config)

        def progress_callback(event: dict[str, Any]) -> None:
            if self.queue.is_scan_cancelled(task.scan_id):
                raise RuntimeError("scan cancelled")
            progress_percent = event.get("progress_percent", 0)
            progress = max(0.0, min(1.0, float(progress_percent) / 100.0))
            self.queue.update_task_progress(task.task_id, progress)
            message = event.get("message")
            if message:
                logger.debug(f"Task {task.task_id} progress: {progress:.1%} - {message}")

        # Execute scan
        engine = Engine(
            session=session,
            progress_callback=progress_callback,
            distributed_mode=True,
            task_id=task.task_id,
        )
        result = engine.detect()

        # Convert to TaskResult
        findings_json = [vars(finding) for finding in result.findings]
        task_result = TaskResult(
            task_id=task.task_id,
            findings=findings_json,
            metadata=result.metadata,
            worker_capabilities=self.capabilities,
            worker_id=self.worker_id,
        )

        logger.info(f"Task {task.task_id} completed with {len(result.findings)} findings")
        return task_result

    def _signal_handler(self, signum: int, frame: Any) -> None:
        """Handle shutdown signals.

        Args:
            signum: Signal number
            frame: Current stack frame
        """
        logger.info(f"Received signal {signum}, shutting down worker")
        self._shutdown_event.set()

    def stop(self) -> None:
        """Stop worker."""
        logger.info(f"Stopping worker {self.worker_id}")
        self._running = False
        self._shutdown_event.set()
        self.queue.disconnect()


def run_worker(
    redis_host: str = "localhost",
    redis_port: int = 6379,
    redis_db: int = 0,
    redis_password: str | None = None,
    worker_id: str | None = None,
) -> None:
    """Run a distributed worker process.

    Args:
        redis_host: Redis host
        redis_port: Redis port
        redis_db: Redis database number
        redis_password: Redis password
        worker_id: Worker ID (auto-generated if not provided)
    """
    worker = DistributedWorker(
        redis_host=redis_host,
        redis_port=redis_port,
        redis_db=redis_db,
        redis_password=redis_password,
        worker_id=worker_id,
    )
    worker.run()


__all__ = ["DistributedWorker", "run_worker"]
