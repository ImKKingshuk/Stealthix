from __future__ import annotations

from pathlib import Path
from typing import Any

from stealthix._tui_runtime.responses import ok_response, output_dir
from stealthix.proxy import ProxyWorkspace


def _workspace(params: dict[str, Any]) -> ProxyWorkspace:
    raw = str(params.get("workspace") or "").strip()
    path = Path(raw).expanduser() if raw else output_dir() / "proxy-workspace"
    return ProxyWorkspace(path)


def handle_proxy_action(action: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if not action.startswith("proxy."):
        return None
    workspace = _workspace(params)
    if action == "proxy.stats":
        return ok_response("Loaded proxy workspace stats.", data=workspace.stats())
    if action == "proxy.search":
        records = workspace.search(
            params.get("query"),
            method=params.get("method"),
            status=params.get("status"),
            tag=params.get("tag"),
            host=params.get("host"),
            limit=int(params.get("limit") or 100),
        )
        return ok_response(
            f"Loaded {len(records)} proxy record(s).",
            data={
                "stats": workspace.stats(),
                "records": [record.to_dict() for record in records],
            },
        )
    if action == "proxy.export":
        format_name = str(params.get("format") or "json").lower()
        path = output_dir() / f"stealthix-proxy-history.{format_name}"
        path.write_text(workspace.export_payload(format=format_name), encoding="utf-8")
        return ok_response(f"Exported proxy history to {path}.", data={"path": str(path)})
    return None
