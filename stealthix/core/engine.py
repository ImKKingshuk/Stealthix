"""Stealthix scanning engine.

Orchestrates detection across SQL, NoSQL, and NewSQL injection vectors.
"""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Callable
from copy import deepcopy
from typing import TYPE_CHECKING, Any

import structlog

from stealthix.core.auth import ensure_authenticated, has_auth
from stealthix.core.checkpoint import CheckpointManager, deserialize_findings, serialize_findings
from stealthix.core.detector_pipeline import (
    DelegatedScan as _DelegatedScan,
)
from stealthix.core.detector_pipeline import (
    DetectionStage,
    DetectionTask,
    DetectorPipelineExecutor,
    RuntimePlanner,
    flatten_stage_results,
    task_key,
)
from stealthix.core.errors import ReconError, StealthixError
from stealthix.core.metrics import get_metrics
from stealthix.core.models import Finding, ScanResult, TargetParam
from stealthix.core.session import ScanSession
from stealthix.core.targeting import discover_target_params
from stealthix.crawler.spider import Spider, SpiderOptions
from stealthix.detection.normalization import normalize_findings

try:
    from stealthix.policy import PolicyEnforcer, PolicyLoader, load_policy

    POLICY_AVAILABLE = True
except ImportError:
    POLICY_AVAILABLE = False

if TYPE_CHECKING:
    pass

# Re-export for backward compatibility
__all__ = ["Engine", "Finding", "ScanResult"]

ProgressCallback = Callable[[dict[str, Any]], None]


def _detected_techniques(findings: list[Finding]) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def add(item: str) -> None:
        if item not in seen:
            seen.add(item)
            ordered.append(item)

    for finding in findings:
        kind = str(finding.kind or "").lower()
        details = finding.details if isinstance(finding.details, dict) else {}
        signals = details.get("signals") if isinstance(details.get("signals"), list) else []
        if kind.endswith("-union"):
            add("union")
        if kind.endswith("-boolean"):
            add("boolean")
        if kind.endswith("-time") or (isinstance(signals, list) and "timing-outlier" in signals):
            add("time")
        if kind.startswith("nosqli-"):
            add("boolean")
    for fallback in ["union", "boolean", "time"]:
        if fallback not in seen:
            ordered.append(fallback)
    return ordered


class Engine:
    """Main scanning engine that coordinates detection modules."""

    def __init__(
        self,
        session: ScanSession,
        *,
        progress_callback: ProgressCallback | None = None,
        distributed_mode: bool = False,
        task_id: str | None = None,
    ) -> None:
        self.session = session
        self.progress_callback = progress_callback
        self.distributed_mode = distributed_mode
        self.task_id = task_id
        self.logger = structlog.get_logger(__name__)
        self.metrics = get_metrics()
        self.policy_enforcer: PolicyEnforcer | None = None
        self._init_policy()

    def _init_policy(self) -> None:
        """Initialize policy enforcement if policy file is specified."""
        if not POLICY_AVAILABLE:
            return

        policy_file = self.session.runtime.get("policy_file")
        if not policy_file:
            return

        try:
            policy = load_policy(policy_file)
            self.policy_enforcer = PolicyEnforcer(policy)
            self.logger.info("policy_loaded", policy=policy.name, file=policy_file)
        except Exception as e:
            self.logger.warning("policy_load_failed", file=policy_file, error=str(e))

    def _emit_progress(
        self, *, phase: str, message: str, progress_percent: int, **extra: Any
    ) -> None:
        if self.progress_callback is None:
            return
        payload = {
            "phase": phase,
            "message": message,
            "progress_percent": max(0, min(100, int(progress_percent))),
            **extra,
        }
        self.progress_callback(payload)

    def _prime_auth(self, *, phase: str, progress_percent: int) -> None:
        if not has_auth(self.session):
            return
        self._emit_progress(
            phase=phase,
            message="Preparing authenticated session…",
            progress_percent=progress_percent,
        )
        ensure_authenticated(self.session, reason=phase)

    def _summarize_result(self, result: ScanResult) -> dict[str, Any]:
        return {
            "target": result.target,
            "finding_count": len(result.findings),
            "finding_kinds": [finding.kind for finding in result.findings],
            "metadata": dict(result.metadata),
        }

    def _checkpoint_manager(self) -> CheckpointManager | None:
        manager = self.session.runtime.get("checkpoint_manager")
        return manager if isinstance(manager, CheckpointManager) else None

    def _resume_payload(self, mode: str | None = None) -> dict[str, Any] | None:
        payload = self.session.runtime.get("checkpoint_resume_payload")
        if not isinstance(payload, dict):
            return None
        if mode is not None and str(payload.get("mode") or "") != mode:
            return None
        return payload

    def _resume_state(self, mode: str | None = None) -> dict[str, Any]:
        payload = self._resume_payload(mode)
        state = payload.get("state") if isinstance(payload, dict) else None
        return dict(state) if isinstance(state, dict) else {}

    def _save_checkpoint(
        self,
        *,
        mode: str,
        status: str,
        state: dict[str, Any],
        input_context: dict[str, Any],
        force: bool = False,
        error: dict[str, Any] | None = None,
    ) -> None:
        manager = self._checkpoint_manager()
        if manager is None:
            return
        checkpoint_state = dict(state)
        checkpoint_state["resume_count"] = int(
            self.session.runtime.get("checkpoint_resume_count", 0) or 0
        )
        self.session.runtime["checkpoint_last_state"] = checkpoint_state
        manager.save_snapshot(
            self.session,
            mode=mode,
            status=status,
            state=checkpoint_state,
            input_context=input_context,
            error=error,
            force=force,
        )

    def _target_spec_key(self, spec: dict[str, Any]) -> str:
        normalized = {
            "url": str(spec.get("url") or ""),
            "method": str(spec.get("method") or "GET").upper(),
            "headers": {
                str(key): str(value)
                for key, value in sorted(dict(spec.get("headers") or {}).items())
            },
            "data": dict(spec.get("data") or {})
            if isinstance(spec.get("data"), dict)
            else spec.get("data"),
            "body_format": str(spec.get("body_format") or "form").lower(),
            "target_params": sorted(str(item) for item in spec.get("target_params") or []),
        }
        return json.dumps(normalized, sort_keys=True, default=str)

    def _task_key(self, stage: DetectionStage, task: DetectionTask) -> str:
        return task_key(stage, task)

    def _flatten_stage_results(
        self, stage_results: list[tuple[int, list[Finding]]]
    ) -> list[Finding]:
        return flatten_stage_results(stage_results)

    def _detect_input_context(self) -> dict[str, Any]:
        payload = self._resume_payload("detect")
        if isinstance(payload, dict) and isinstance(payload.get("input_context"), dict):
            return dict(payload["input_context"])
        return {
            "base_url": self.session.config.base_url,
            "method": self.session.config.method,
            "body_format": self.session.config.body_format,
            "target_params": list(self.session.config.target_params or []),
        }

    def _save_detect_checkpoint(
        self,
        *,
        stage_phase: str,
        findings: list[Finding],
        completed_task_ids: list[str],
        all_task_ids: list[str],
        total_tasks: int,
        status: str = "running",
        force: bool = False,
        result_summary: dict[str, Any] | None = None,
    ) -> None:
        completed_set = set(completed_task_ids)
        pending_task_ids = [task_id for task_id in all_task_ids if task_id not in completed_set]
        progress_percent = (
            100
            if status == "completed"
            else 10 + int((len(completed_set) * 89) / max(1, total_tasks))
        )
        state = {
            "findings": serialize_findings(findings),
            "completed_task_ids": list(completed_task_ids),
            "queue": {
                "completed_task_ids": list(completed_task_ids),
                "pending_task_ids": pending_task_ids,
            },
            "progress": {
                "mode": "detect",
                "current_phase": stage_phase,
                "completed_tasks": len(completed_set),
                "total_tasks": total_tasks,
                "progress_percent": progress_percent,
            },
        }
        if result_summary is not None:
            state["result_summary"] = result_summary
        self._save_checkpoint(
            mode="detect",
            status=status,
            state=state,
            input_context=self._detect_input_context(),
            force=force,
        )

    def _scan_specs(
        self,
        specs_input: list[Any],
        *,
        mode: str,
        input_context: dict[str, Any] | None = None,
    ) -> ScanResult:
        specs = [self._coerce_target_spec(item) for item in specs_input if item]
        if not specs:
            return self.detect()
        self._prime_auth(phase="Authentication", progress_percent=1)
        deduped_specs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for spec in specs:
            key = self._target_spec_key(spec)
            if key in seen:
                continue
            seen.add(key)
            deduped_specs.append(spec)

        resume_state = self._resume_state(mode)
        all_findings = deserialize_findings(
            resume_state.get("findings") if isinstance(resume_state.get("findings"), list) else None
        )
        per_target_results = [
            item for item in resume_state.get("per_target_results", []) if isinstance(item, dict)
        ]
        completed_target_keys = [
            str(item) for item in resume_state.get("completed_target_keys", []) if str(item)
        ]
        completed_target_set = set(completed_target_keys)
        total = len(deduped_specs)
        checkpoint_input = dict(input_context or {})
        checkpoint_input["specs"] = deduped_specs

        self._emit_progress(
            phase="Multi-target Planning",
            message=f"Prepared {total} target(s) for scanning.",
            progress_percent=2,
            target_count=total,
            completed_targets=len(completed_target_set),
        )
        self._save_checkpoint(
            mode=mode,
            status="running",
            state={
                "findings": serialize_findings(all_findings),
                "per_target_results": per_target_results,
                "completed_target_keys": completed_target_keys,
                "queue": {
                    "completed_target_keys": completed_target_keys,
                    "pending_target_specs": [
                        spec
                        for spec in deduped_specs
                        if self._target_spec_key(spec) not in completed_target_set
                    ],
                },
                "progress": {
                    "mode": mode,
                    "current_phase": "Multi-target Planning",
                    "completed_targets": len(completed_target_set),
                    "total_targets": total,
                    "progress_percent": int((len(completed_target_set) * 100) / max(1, total)),
                },
            },
            input_context=checkpoint_input,
            force=True,
        )

        for index, spec in enumerate(deduped_specs, start=1):
            key = self._target_spec_key(spec)
            if key in completed_target_set:
                continue
            result = self._run_target_scan(spec, index=index, total=total)
            all_findings.extend(result.findings)
            per_target_results.append(self._summarize_result(result))
            completed_target_keys.append(key)
            completed_target_set.add(key)
            self._save_checkpoint(
                mode=mode,
                status="running",
                state={
                    "findings": serialize_findings(all_findings),
                    "per_target_results": per_target_results,
                    "completed_target_keys": completed_target_keys,
                    "queue": {
                        "completed_target_keys": completed_target_keys,
                        "pending_target_specs": [
                            item
                            for item in deduped_specs
                            if self._target_spec_key(item) not in completed_target_set
                        ],
                    },
                    "progress": {
                        "mode": mode,
                        "current_phase": f"Target {index}/{total}",
                        "completed_targets": len(completed_target_set),
                        "total_targets": total,
                        "progress_percent": int((len(completed_target_set) * 100) / max(1, total)),
                    },
                },
                input_context=checkpoint_input,
            )

        findings = normalize_findings(all_findings)
        self.session.metadata["detected_techniques"] = _detected_techniques(findings)
        self.session.metadata["multi_target"] = True
        self.session.metadata["scanned_targets"] = [
            {
                "url": str(spec.get("url") or ""),
                "method": str(spec.get("method") or "GET").upper(),
                "target_params": list(spec.get("target_params") or []),
                "origin": (spec.get("metadata") or {}).get("origin"),
            }
            for spec in deduped_specs
        ]
        self.session.metadata["per_target_results"] = per_target_results
        self._emit_progress(
            phase="Complete",
            message=f"Completed multi-target scan with {len(findings)} finding(s).",
            progress_percent=100,
            target_count=total,
            finding_count=len(findings),
        )
        result = ScanResult(
            target=self.session.config.base_url,
            findings=findings,
            metadata=dict(self.session.metadata),
        )
        self._save_checkpoint(
            mode=mode,
            status="completed",
            state={
                "findings": serialize_findings(result.findings),
                "per_target_results": per_target_results,
                "completed_target_keys": completed_target_keys,
                "queue": {
                    "completed_target_keys": completed_target_keys,
                    "pending_target_specs": [],
                },
                "progress": {
                    "mode": mode,
                    "current_phase": "Complete",
                    "completed_targets": total,
                    "total_targets": total,
                    "progress_percent": 100,
                },
                "result_summary": self._summarize_result(result),
            },
            input_context=checkpoint_input,
            force=True,
        )
        return result

    def _coerce_target_spec(self, item: Any) -> dict[str, Any]:
        if isinstance(item, str):
            return {
                "url": item,
                "method": "GET",
                "headers": {},
                "data": None,
                "body_format": "form",
                "target_params": None,
                "metadata": {"origin": "scan-list"},
            }
        if isinstance(item, dict):
            return {
                "url": str(
                    item.get("url") or item.get("base_url") or self.session.config.base_url
                ).strip(),
                "method": str(item.get("method") or "GET").upper(),
                "headers": dict(item.get("headers") or {}),
                "data": item.get("data") if isinstance(item.get("data"), dict) else None,
                "body_format": str(item.get("body_format") or "form").lower(),
                "target_params": [str(value) for value in item.get("target_params") or []] or None,
                "metadata": dict(item.get("metadata") or {}),
            }
        raise TypeError(f"Unsupported target spec: {type(item)!r}")

    def _build_target_session(self, spec: dict[str, Any]) -> ScanSession:
        session = self.session.clone_for_worker()
        session.config.base_url = str(spec.get("url") or session.config.base_url)
        session.config.method = str(spec.get("method") or "GET").upper()
        session.config.headers.update(dict(spec.get("headers") or {}))
        session.config.data = spec.get("data") if isinstance(spec.get("data"), dict) else None
        session.config.body_format = str(
            spec.get("body_format") or session.config.body_format or "form"
        ).lower()
        session.config.target_params = [
            str(item) for item in spec.get("target_params") or []
        ] or None
        session.config.api_schema = None
        metadata = spec.get("metadata") if isinstance(spec.get("metadata"), dict) else {}
        session.metadata.setdefault("crawl", {})
        if isinstance(metadata, dict):
            session.metadata.update(metadata)
        session.metadata["scan_target"] = {
            "url": session.config.base_url,
            "method": session.config.method,
            "body_format": session.config.body_format,
            "target_params": list(session.config.target_params or []),
        }
        return session

    def _run_target_scan(self, spec: dict[str, Any], *, index: int, total: int) -> ScanResult:
        target_session = self._build_target_session(spec)
        target_label = f"{target_session.config.method} {target_session.config.base_url}"

        def on_progress(payload: dict[str, Any]) -> None:
            child_percent = int(payload.get("progress_percent", 0))
            overall = int((((index - 1) * 100) + child_percent) / max(1, total))
            self._emit_progress(
                phase=f"Target {index}/{total}",
                message=f"{target_label} · {payload.get('message') or payload.get('phase') or 'Scanning'}",
                progress_percent=overall,
                target_index=index,
                target_count=total,
                target_url=target_session.config.base_url,
                target_method=target_session.config.method,
            )

        result = Engine(target_session, progress_callback=on_progress).detect()
        self.session.merge_worker_state(target_session)
        return result

    def scan_list(self, urls: list[Any]) -> ScanResult:
        return self._scan_specs(list(urls), mode="scan_list", input_context={"specs": list(urls)})

    def scan_site(
        self,
        base_url: str | None = None,
        *,
        depth: int = 2,
        max_pages: int = 50,
        scope: str = "host",
        parse_robots: bool = True,
        parse_sitemap: bool = True,
    ) -> ScanResult:
        self._prime_auth(phase="Authentication", progress_percent=1)
        crawl_options = {
            "depth": max(0, int(depth)),
            "max_pages": max(1, int(max_pages)),
            "scope": str(scope or "host").lower(),
            "parse_robots": bool(parse_robots),
            "parse_sitemap": bool(parse_sitemap),
        }
        resume_payload = self._resume_payload("scan_site")
        resume_input = (
            dict(resume_payload.get("input_context") or {})
            if isinstance(resume_payload, dict)
            else {}
        )
        saved_crawl = (
            resume_input.get("crawl_result")
            if isinstance(resume_input.get("crawl_result"), dict)
            else None
        )
        if saved_crawl is not None:
            self._emit_progress(
                phase="Crawl",
                message="Reusing checkpointed crawl result…",
                progress_percent=1,
            )
            crawl_result = saved_crawl
        else:
            spider = Spider(
                self.session,
                options=SpiderOptions(
                    max_depth=crawl_options["depth"],
                    max_pages=crawl_options["max_pages"],
                    scope=crawl_options["scope"],
                    parse_robots=crawl_options["parse_robots"],
                    parse_sitemap=crawl_options["parse_sitemap"],
                ),
            )
            self._emit_progress(
                phase="Crawl",
                message=f"Crawling {base_url or self.session.config.base_url}…",
                progress_percent=1,
            )
            crawl_result = spider.crawl(base_url or self.session.config.base_url)
        targets = list(crawl_result.get("targets") or [])
        if not targets:
            targets = [
                {
                    "url": crawl_result.get("base_url") or self.session.config.base_url,
                    "method": self.session.config.method,
                    "data": self.session.config.data,
                    "body_format": self.session.config.body_format,
                    "target_params": self.session.config.target_params,
                    "metadata": {"origin": "crawl-fallback"},
                }
            ]
        result = self._scan_specs(
            targets,
            mode="scan_site",
            input_context={
                "crawl_options": crawl_options,
                "crawl_result": crawl_result,
            },
        )
        result.metadata["site_scan"] = True
        result.metadata["crawl"] = crawl_result
        return result

    def _prepare_runtime(
        self,
    ) -> tuple[dict[str, Any] | None, list[TargetParam], list[DetectionStage]]:
        plan = RuntimePlanner(
            self.session,
            emit_progress=self._emit_progress,
            recon_enabled=self._recon_enabled,
            run_reconnaissance=self._run_reconnaissance,
            discover_targets=discover_target_params,
        ).prepare()
        return plan.plugin, list(plan.selected_targets), list(plan.stages)

    def _execute_task(self, task: DetectionTask) -> tuple[int, list[Finding], ScanSession]:
        return DetectorPipelineExecutor(
            self.session,
            emit_progress=self._emit_progress,
            save_detect_checkpoint=self._save_detect_checkpoint,
            logger=self.logger,
        ).execute_task(task)

    def _execute_stage(
        self,
        stage: DetectionStage,
        *,
        findings_so_far: list[Finding],
        completed_tasks: int,
        total_tasks: int,
        completed_task_ids: list[str],
        all_task_ids: list[str],
    ) -> tuple[list[Finding], int, list[str]]:
        return DetectorPipelineExecutor(
            self.session,
            emit_progress=self._emit_progress,
            save_detect_checkpoint=self._save_detect_checkpoint,
            logger=self.logger,
        ).execute_stage(
            stage,
            findings_so_far=findings_so_far,
            completed_tasks=completed_tasks,
            total_tasks=total_tasks,
            completed_task_ids=completed_task_ids,
            all_task_ids=all_task_ids,
        )

    def _finalize_result(self, findings: list[Finding]) -> ScanResult:
        findings = normalize_findings(findings)
        self.session.metadata["detected_techniques"] = _detected_techniques(findings)
        for finding in findings:
            details = getattr(finding, "details", {}) or {}
            if isinstance(details, dict) and details.get("parameter") and details.get("location"):
                self.session.metadata.setdefault(
                    "injection",
                    {"parameter": details["parameter"], "location": details["location"]},
                )
                break
        self._emit_progress(
            phase="Finalize",
            message="Finalizing scan result…",
            progress_percent=99,
            finding_count=len(findings),
        )
        return ScanResult(
            target=self.session.config.base_url,
            findings=findings,
            metadata=dict(self.session.metadata),
        )

    def _recon_enabled(self) -> bool:
        """Check if reconnaissance is enabled."""
        return self.session.metadata.get("recon_enabled", True)

    def _run_reconnaissance(self) -> None:
        """Execute reconnaissance phase."""
        from stealthix.recon.engine import ReconEngine
        from stealthix.recon.models import ReconConfig

        config = ReconConfig(
            enabled=self.session.metadata.get("recon_enabled", True),
            tech_enabled=self.session.metadata.get("recon_tech_enabled", True),
            endpoints_enabled=self.session.metadata.get("recon_endpoints_enabled", True),
            wordlist_path=self.session.metadata.get("recon_wordlist_path"),
            max_endpoints=self.session.metadata.get("recon_max_endpoints", 100),
            depth=self.session.metadata.get("recon_depth", 2),
            timeout=self.session.metadata.get("recon_timeout"),
        )

        self._emit_progress(
            phase="Reconnaissance",
            message="Detecting technologies and discovering endpoints…",
            progress_percent=3,
        )

        try:
            engine = ReconEngine(
                self.session, config=config, progress_callback=self.progress_callback
            )
            results = engine.run()

            # Store in session metadata
            self.session.metadata["recon"] = results

            # Apply reconnaissance insights
            self._apply_recon_insights(results)

        except (ImportError, AttributeError) as exc:
            self.logger.warning(
                "reconnaissance_not_available",
                error=str(exc),
            )
            self.session.metadata.setdefault("recon_errors", []).append(str(exc))
        except ReconError as exc:
            self.logger.error(
                "reconnaissance_failed",
                error=str(exc),
                exc_info=True,
            )
            self.session.metadata.setdefault("recon_errors", []).append(str(exc))

    def _apply_recon_insights(self, results: dict[str, Any]) -> None:
        """Apply reconnaissance results to scan configuration."""
        # Enable adaptive evasion if WAF detected
        techs = results.get("technologies", [])
        for tech in techs:
            if tech.get("category") == "cdn_waf":
                self.session.config.tamper_auto = True
                break

        # Prioritize DBMS if detected
        for tech in techs:
            if tech.get("category") == "database" and not self.session.config.dbms:
                self.session.config.dbms = tech.get("name")
                break

    def detect(self) -> ScanResult:
        """Run all detection modules and aggregate findings."""
        scan_id = self.session.runtime.get("scan_id", "unknown")
        self.logger.info(
            "scan_started",
            scan_id=scan_id,
            target=self.session.config.base_url,
            method=self.session.config.method,
            level=self.session.config.level,
        )
        self.metrics.start_scan()

        resume_state = self._resume_state("detect")
        findings = deserialize_findings(
            resume_state.get("findings") if isinstance(resume_state.get("findings"), list) else None
        )
        self._prime_auth(phase="Authentication", progress_percent=1)
        try:
            _plugin_dict, _chosen, stages = self._prepare_runtime()
        except _DelegatedScan as delegated:
            return self.scan_list(delegated.targets)
        all_task_ids = [self._task_key(stage, task) for stage in stages for task in stage.tasks]
        completed_task_ids = [
            task_id
            for task_id in resume_state.get("completed_task_ids", [])
            if str(task_id) in set(all_task_ids)
        ]
        completed_task_set = set(completed_task_ids)
        stages = [
            DetectionStage(
                phase=stage.phase,
                message=stage.message,
                tasks=tuple(
                    task
                    for task in stage.tasks
                    if self._task_key(stage, task) not in completed_task_set
                ),
                condition=stage.condition,
            )
            for stage in stages
        ]
        total_tasks = sum(len(stage.tasks) for stage in stages) or 1
        completed_tasks = len(completed_task_ids)
        self._save_detect_checkpoint(
            stage_phase="Planning",
            findings=findings,
            completed_task_ids=completed_task_ids,
            all_task_ids=all_task_ids,
            total_tasks=max(total_tasks, len(all_task_ids) or 1),
            force=True,
        )

        for stage in stages:
            stage_findings, completed_tasks, completed_task_ids = self._execute_stage(
                stage,
                findings_so_far=findings,
                completed_tasks=completed_tasks,
                total_tasks=max(total_tasks, len(all_task_ids) or 1),
                completed_task_ids=completed_task_ids,
                all_task_ids=all_task_ids,
            )
            findings.extend(stage_findings)

            # Enforce policy after each stage if configured
            if self.policy_enforcer:
                violations = self.policy_enforcer.enforce(findings)
                if self.policy_enforcer.should_fail_scan(violations):
                    self.logger.error(
                        "policy_violation_scan_failed",
                        violation_count=len(violations),
                        violations=[v.message for v in violations],
                    )
                    # Create result with current findings and policy violations
                    result = self._finalize_result(findings)
                    result.metadata["policy_violations"] = [v.message for v in violations]
                    result.metadata["policy_failed"] = True
                    return result

        result = self._finalize_result(findings)

        # Track findings in metrics
        for finding in result.findings:
            severity = getattr(finding, "severity", "Unknown")
            finding_type = str(finding.kind) if hasattr(finding, "kind") else "Unknown"
            self.metrics.increment_finding(severity, finding_type)

        self.metrics.end_scan()

        self.logger.info(
            "scan_completed",
            scan_id=scan_id,
            target=self.session.config.base_url,
            finding_count=len(result.findings),
            duration_seconds=self.metrics.get_metrics_snapshot()["scan"]["duration_seconds"],
        )

        self._save_detect_checkpoint(
            stage_phase="Complete",
            findings=result.findings,
            completed_task_ids=all_task_ids,
            all_task_ids=all_task_ids,
            total_tasks=max(len(all_task_ids), 1),
            status="completed",
            force=True,
            result_summary=self._summarize_result(result),
        )
        self._emit_progress(
            phase="Complete",
            message=f"Completed with {len(result.findings)} finding(s).",
            progress_percent=100,
            completed_tasks=total_tasks,
            total_tasks=total_tasks,
            finding_count=len(result.findings),
        )
        return result
