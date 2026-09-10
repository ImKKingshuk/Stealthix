"""
Reconnaissance engine orchestration.
"""

import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from stealthix.core.session import ScanSession
from stealthix.recon.endpoint_discovery import EndpointDiscovery
from stealthix.recon.models import ReconConfig
from stealthix.recon.tech_detector import TechDetector


class ReconEngine:
    """Orchestrates reconnaissance operations."""

    def __init__(
        self,
        session: ScanSession,
        *,
        config: ReconConfig | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
    ):
        self.session = session
        self.config = config or ReconConfig()
        self.progress_callback = progress_callback

    def run(self) -> dict[str, Any]:
        """
        Execute reconnaissance and return results.

        Returns:
            {
                "technologies": [...],
                "endpoints": [...],
                "fingerprint": {...},
                "elapsed": float,
                "errors": [...]
            }
        """
        start_time = time.time()
        results: dict[str, Any] = {
            "technologies": [],
            "endpoints": [],
            "fingerprint": {},
            "elapsed": 0.0,
            "errors": [],
        }

        try:
            # Run technology detection if enabled
            if self.config.tech_enabled:
                self._emit_progress("Tech Detection", "Detecting technologies...", 10)
                tech_results = self._run_tech_detection()
                results["technologies"] = tech_results

            # Run endpoint discovery if enabled
            if self.config.endpoints_enabled:
                self._emit_progress("Endpoint Discovery", "Discovering endpoints...", 50)
                endpoint_results = self._run_endpoint_discovery()
                results["endpoints"] = endpoint_results

            # Build fingerprint summary
            results["fingerprint"] = self._build_fingerprint_summary(results)

        except Exception as exc:
            results["errors"].append(f"Reconnaissance failed: {exc}")

        results["elapsed"] = time.time() - start_time
        results["errors"] = self.session.metadata.get("recon_errors", [])

        return results

    def _run_tech_detection(self) -> list[dict[str, Any]]:
        """Execute Tech_Detector."""
        try:
            detector = TechDetector(self.session)
            matches = detector.detect()
            return [match.to_dict() for match in matches]
        except Exception as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Technology detection failed: {exc}"
            )
            return []

    def _run_endpoint_discovery(self) -> list[dict[str, Any]]:
        """Execute Endpoint_Discovery."""
        try:
            discovery = EndpointDiscovery(self.session, self.config)
            endpoints = discovery.discover()
            return [ep.to_dict() for ep in endpoints]
        except Exception as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Endpoint discovery failed: {exc}"
            )
            return []

    def _build_fingerprint_summary(self, results: dict[str, Any]) -> dict[str, Any]:
        """Build fingerprint summary from detection results."""
        fingerprint: dict[str, Any] = {}

        technologies = results.get("technologies", [])
        for tech in technologies:
            category = tech.get("category")
            name = tech.get("name")
            version = tech.get("version")

            if category == "web_server":
                fingerprint["server"] = f"{name}/{version}" if version else name
            elif category == "language":
                fingerprint["powered_by"] = f"{name}/{version}" if version else name
            elif category == "os":
                fingerprint["os"] = name
            elif category == "cdn_waf":
                fingerprint.setdefault("waf_hints", []).append(name)
            elif category == "database":
                fingerprint.setdefault("database_hints", []).append(name)

        return fingerprint

    def _emit_progress(self, phase: str, message: str, progress_percent: int):
        """Emit progress callback if registered."""
        if self.progress_callback:
            try:
                self.progress_callback(
                    {
                        "phase": phase,
                        "message": message,
                        "progress_percent": progress_percent,
                    }
                )
            except Exception:
                pass  # Don't fail on callback errors
