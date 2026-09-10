from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

from stealthix.core.engine import Engine
from stealthix.core.models import ScanResult
from stealthix.core.session import ScanSession

from .estimation import estimate_total_requests, summarize_tested_params
from .responses import timestamp
from .serialization import result_to_dict, session_to_dict


@dataclass
class ScanJob:
    job_id: str
    session: ScanSession
    status: str = "queued"
    message: str = "Queued"
    started_at: str | None = None
    finished_at: str | None = None
    result: ScanResult | None = None
    error: str | None = None
    logs: list[dict[str, str]] = field(default_factory=list)
    thread: threading.Thread | None = None
    phase: str = "Queued"
    phase_percent: int = 0
    estimated_total_requests: int = 0
    started_monotonic: float | None = None


class ScanJobStore:
    def __init__(self) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.RLock()

    def _append_log(self, job: ScanJob, level: str, message: str) -> None:
        job.logs.append({"level": level, "message": message})
        if len(job.logs) > 100:
            job.logs[:] = job.logs[-100:]

    def _set_phase(
        self, job: ScanJob, phase: str, percent: int, message: str | None = None
    ) -> None:
        job.phase = phase
        job.phase_percent = max(0, min(100, int(percent)))
        if message:
            job.message = message
            self._append_log(job, "info", message)

    def _run_detection(self, job: ScanJob) -> ScanResult:
        session = job.session
        engine = Engine(session)
        metadata = session.metadata if isinstance(session.metadata, dict) else {}
        crawl_targets = (
            metadata.get("crawl_targets") if isinstance(metadata.get("crawl_targets"), list) else []
        )
        crawl_options = (
            metadata.get("crawl_options") if isinstance(metadata.get("crawl_options"), dict) else {}
        )
        crawl_options = crawl_options if isinstance(crawl_options, dict) else {}
        if crawl_targets:
            job.estimated_total_requests = sum(
                estimate_total_requests(
                    engine._build_target_session(engine._coerce_target_spec(item))
                )
                for item in crawl_targets
            )
        else:
            job.estimated_total_requests = estimate_total_requests(session)

        def on_progress(payload: dict[str, Any]) -> None:
            phase = str(payload.get("phase") or job.phase)
            percent = int(payload.get("progress_percent", job.phase_percent))
            message = str(payload.get("message") or job.message)
            with self._lock:
                if message != job.message or phase != job.phase:
                    self._append_log(job, "info", message)
                job.phase = phase
                job.phase_percent = max(0, min(100, percent))
                job.message = message

        engine = Engine(session, progress_callback=on_progress)
        if crawl_targets:
            return engine.scan_list(crawl_targets)
        if crawl_options.get("enabled"):
            return engine.scan_site(
                session.config.base_url,
                depth=int(crawl_options.get("depth", 2)),
                max_pages=int(crawl_options.get("max_pages", 50)),
                scope=str(crawl_options.get("scope") or "host"),
                parse_robots=bool(crawl_options.get("parse_robots", True)),
                parse_sitemap=bool(crawl_options.get("parse_sitemap", True)),
            )
        return engine.detect()

    def start(self, session: ScanSession) -> ScanJob:
        job = ScanJob(job_id=uuid.uuid4().hex, session=session)
        self._append_log(job, "info", "Scan queued")
        with self._lock:
            self._jobs[job.job_id] = job

        def worker() -> None:
            job.status = "running"
            job.started_at = timestamp()
            job.started_monotonic = time.monotonic()
            job.message = "Running detection engine"
            self._append_log(job, "info", "TUI scan runtime started")
            try:
                result = self._run_detection(job)
                result.metadata.setdefault("generated_at", timestamp())
                result.metadata.setdefault("request_history", session.history.to_list())
                result.metadata.setdefault("scanned_targets", [result.target])
                job.result = result
                job.status = "done"
                job.phase = "Complete"
                job.phase_percent = 100
                job.message = f"Completed with {len(result.findings)} finding(s)"
                self._append_log(job, "info", job.message)
            except Exception as exc:  # pragma: no cover
                if session.control.cancel.is_set():
                    job.status = "cancelled"
                    job.message = "Scan cancelled"
                    self._append_log(job, "warning", job.message)
                else:
                    job.status = "failed"
                    job.error = str(exc)
                    job.message = f"Scan failed: {exc}"
                    self._append_log(job, "error", job.message)
            finally:
                job.finished_at = timestamp()

        job.thread = threading.Thread(
            target=worker, name=f"stealthix-scan-{job.job_id[:8]}", daemon=True
        )
        job.thread.start()
        return job

    def get(self, job_id: str) -> ScanJob:
        with self._lock:
            if job_id not in self._jobs:
                raise KeyError(f"unknown job: {job_id}")
            return self._jobs[job_id]

    def cancel(self, job_id: str) -> ScanJob:
        job = self.get(job_id)
        job.session.control.request_cancel()
        if job.status not in {"done", "failed", "cancelled"}:
            job.status = "cancel_requested"
            job.message = "Cancellation requested"
            self._append_log(job, "warning", job.message)
        return job

    def pause(self, job_id: str) -> ScanJob:
        job = self.get(job_id)
        if job.status not in {"done", "failed", "cancelled"}:
            job.session.control.set_paused(True)
            job.status = "paused"
            job.message = "Scan paused"
            self._append_log(job, "warning", job.message)
        return job

    def resume(self, job_id: str) -> ScanJob:
        job = self.get(job_id)
        if job.status not in {"done", "failed", "cancelled"}:
            job.session.control.set_paused(False)
            job.status = "running"
            job.message = "Scan resumed"
            self._append_log(job, "info", job.message)
        return job


JOBS = ScanJobStore()


def job_payload(job: ScanJob) -> dict[str, Any]:
    request_count = len(job.session.history)
    tested_params, tested_params_summary = summarize_tested_params(job.session)
    active_elapsed = (
        job.session.control.active_elapsed(job.started_monotonic)
        if job.started_monotonic is not None
        else 0.0
    )
    eta_seconds = None
    if request_count > 0 and active_elapsed > 0.0 and job.estimated_total_requests > request_count:
        eta_seconds = int(
            max(
                0.0,
                (job.estimated_total_requests - request_count)
                * (active_elapsed / max(1, request_count)),
            )
        )
    request_percent = (
        int((request_count * 100) / max(1, job.estimated_total_requests))
        if job.estimated_total_requests
        else 0
    )
    progress_percent = (
        100 if job.status == "done" else max(job.phase_percent, min(99, request_percent))
    )
    return {
        "job_id": job.job_id,
        "status": job.status,
        "message": job.message,
        "error": job.error,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "finding_count": len(job.result.findings) if job.result else 0,
        "result": result_to_dict(job.result) if job.result else None,
        "session": session_to_dict(job.session),
        "phase": job.phase,
        "progress_percent": progress_percent,
        "request_count": request_count,
        "estimated_total_requests": job.estimated_total_requests,
        "eta_seconds": eta_seconds,
        "active_elapsed_seconds": round(active_elapsed, 2),
        "paused": not job.session.control.pause.is_set(),
        "tested_params": tested_params,
        "tested_params_summary": tested_params_summary,
    }
