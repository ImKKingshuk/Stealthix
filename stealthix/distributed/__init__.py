"""Distributed scanning support for Stealthix.

This module provides distributed worker architecture using Redis for task queue,
enabling horizontal scaling across multiple worker nodes for parallel scanning.
"""

from stealthix.distributed.coordinator import ScanCoordinator
from stealthix.distributed.models import ScanTask, TaskArtifact, TaskResult, WorkerCapabilities
from stealthix.distributed.queue import RedisTaskQueue
from stealthix.distributed.worker import DistributedWorker, run_worker

__all__ = [
    "ScanCoordinator",
    "ScanTask",
    "TaskArtifact",
    "TaskResult",
    "WorkerCapabilities",
    "RedisTaskQueue",
    "DistributedWorker",
    "run_worker",
]
