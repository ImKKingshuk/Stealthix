from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from stealthix.core.session import ScanSession, SessionConfig
from stealthix.recon.engine import ReconEngine
from stealthix.recon.models import ReconConfig


def recon_tech(args: Any) -> dict[str, Any]:
    """Execute technology detection reconnaissance."""
    # Build minimal session config
    session_config = SessionConfig(
        base_url=args.url,
        proxy=getattr(args, "proxy", None),
        timeout=float(getattr(args, "timeout", 10.0)),
        verify_tls=bool(getattr(args, "verify_tls", True)),
    )
    session = ScanSession(session_config)

    # Build recon config
    recon_config = ReconConfig(
        tech_enabled=True,
        endpoints_enabled=False,
        timeout=session_config.timeout,
    )

    # Execute reconnaissance
    engine = ReconEngine(session, config=recon_config)
    results = engine.run()

    return {
        "target": args.url,
        "technologies": [
            {
                "category": tech["category"] if isinstance(tech, dict) else tech.category,
                "name": tech["name"] if isinstance(tech, dict) else tech.name,
                "version": tech.get("version") if isinstance(tech, dict) else tech.version,
                "confidence": tech["confidence"] if isinstance(tech, dict) else tech.confidence,
                "evidence_count": (
                    len(tech.get("evidence", []))
                    if isinstance(tech, dict)
                    else len(getattr(tech, "evidence", []))
                ),
            }
            for tech in results.get("technologies", [])
        ],
        "fingerprint": results.get("fingerprint", {}),
        "elapsed": results.get("elapsed", 0.0),
    }


def recon_endpoints(args: Any) -> dict[str, Any]:
    """Execute endpoint discovery reconnaissance."""
    # Build minimal session config
    session_config = SessionConfig(
        base_url=args.url,
        proxy=getattr(args, "proxy", None),
        timeout=float(getattr(args, "timeout", 10.0)),
        verify_tls=bool(getattr(args, "verify_tls", True)),
    )
    session = ScanSession(session_config)

    # Build recon config
    recon_config = ReconConfig(
        tech_enabled=False,
        endpoints_enabled=True,
        wordlist_path=getattr(args, "wordlist", None),
        max_endpoints=int(getattr(args, "max_endpoints", 100)),
        depth=int(getattr(args, "depth", 2)),
        timeout=session_config.timeout,
    )

    # Execute reconnaissance
    engine = ReconEngine(session, config=recon_config)
    results = engine.run()

    return {
        "target": args.url,
        "endpoints": [
            {
                "url": endpoint["url"] if isinstance(endpoint, dict) else endpoint.url,
                "status_code": (
                    endpoint["status_code"]
                    if isinstance(endpoint, dict)
                    else endpoint.status_code
                ),
                "response_size": (
                    endpoint.get("response_size", 0)
                    if isinstance(endpoint, dict)
                    else getattr(endpoint, "response_size", 0)
                ),
                "response_time": (
                    endpoint.get("response_time", 0.0)
                    if isinstance(endpoint, dict)
                    else getattr(endpoint, "response_time", 0.0)
                ),
                "category": (
                    endpoint.get("category", "")
                    if isinstance(endpoint, dict)
                    else getattr(endpoint, "category", "")
                ),
                "confidence": (
                    endpoint.get("confidence", 0.0)
                    if isinstance(endpoint, dict)
                    else getattr(endpoint, "confidence", 0.0)
                ),
            }
            for endpoint in results.get("endpoints", [])
        ],
        "elapsed": results.get("elapsed", 0.0),
    }


def format_recon_output(data: dict[str, Any], format_type: str) -> str:
    """Format reconnaissance output for display."""
    if format_type == "json":
        return json.dumps(data, indent=2, sort_keys=True)

    # Text format
    lines = []
    lines.append(f"Target: {data.get('target', 'N/A')}")
    lines.append(f"Elapsed: {data.get('elapsed', 0.0):.2f}s")
    lines.append("")

    if "technologies" in data:
        lines.append(f"Technologies Detected: {len(data['technologies'])}")
        lines.append("-" * 80)
        for tech in data["technologies"]:
            version = tech.get("version") or "N/A"
            lines.append(
                f"  {tech['category']:15} | {tech['name']:20} | v{version:10} | Confidence: {tech['confidence']:.2f}"
            )
        lines.append("")

        if data.get("fingerprint"):
            lines.append("Fingerprint Summary:")
            fp = data["fingerprint"]
            if fp.get("server"):
                lines.append(f"  Server: {fp['server']}")
            if fp.get("powered_by"):
                lines.append(f"  Powered-By: {fp['powered_by']}")
            if fp.get("os"):
                lines.append(f"  OS: {fp['os']}")
            if fp.get("waf_hints"):
                lines.append(f"  WAF Hints: {', '.join(fp['waf_hints'])}")
            if fp.get("database_hints"):
                lines.append(f"  Database Hints: {', '.join(fp['database_hints'])}")

    if "endpoints" in data:
        lines.append(f"Endpoints Discovered: {len(data['endpoints'])}")
        lines.append("-" * 80)
        for endpoint in data["endpoints"]:
            lines.append(
                f"  [{endpoint['status_code']}] {endpoint['url']:60} | {endpoint['category']:15} | Confidence: {endpoint['confidence']:.2f}"
            )

    return "\n".join(lines)


__all__ = ["recon_tech", "recon_endpoints", "format_recon_output"]
