"""Pydantic models for distributed task serialization."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class ScanTask(BaseModel):
    """Represents a scan task for distributed execution."""

    model_config = ConfigDict()

    task_id: str = Field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    target: str
    scan_config: dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=0, ge=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    status: str = Field(default="pending")  # pending, running, completed, failed


class TaskArtifact(BaseModel):
    """Durable artifact produced by a distributed task."""

    model_config = ConfigDict()

    kind: str
    uri: str
    media_type: str | None = None
    sha256: str | None = None
    size_bytes: int | None = Field(default=None, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)


class WorkerCapabilities(BaseModel):
    """Capabilities advertised by a distributed worker."""

    model_config = ConfigDict()

    worker_id: str
    version: str | None = None
    platform: str | None = None
    python: str | None = None
    rust_core: bool = False
    detectors: list[str] = Field(default_factory=list)
    extras: list[str] = Field(default_factory=list)


class TaskResult(BaseModel):
    """Represents the result of a completed scan task."""

    model_config = ConfigDict()

    task_id: str
    findings: list[dict[str, Any]] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    artifacts: list[TaskArtifact] = Field(default_factory=list)
    worker_capabilities: WorkerCapabilities | None = None
    completed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    worker_id: str
    error: str | None = None


__all__ = ["ScanTask", "TaskArtifact", "TaskResult", "WorkerCapabilities"]
