from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from stealthix._tui_callback_runtime import ok_response, output_dir, result_from_payload
from stealthix.reporting.csv_report import render_csv
from stealthix.reporting.html import render_html
from stealthix.reporting.json_report import render_json
from stealthix.reporting.junit import render_junit
from stealthix.reporting.markdown import render_markdown
from stealthix.reporting.pdf import render_pdf
from stealthix.reporting.sarif import render_sarif


def _timestamp_slug() -> str:
    return datetime.now(UTC).strftime("%Y%m%d-%H%M%S")


def handle_report_action(action: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if action != "report.export":
        return None
    format_name = str(params.get("format") or "json").strip().lower()
    result_payload = params.get("result")
    if not isinstance(result_payload, dict):
        raise ValueError("report.export requires a serialized result")
    result = result_from_payload(result_payload)

    base_path = output_dir() / f"stealthix-report-{_timestamp_slug()}"
    if format_name == "json":
        path = base_path.with_suffix(".json")
        path.write_text(render_json(result), encoding="utf-8")
    elif format_name == "markdown":
        path = base_path.with_suffix(".md")
        path.write_text(render_markdown(result), encoding="utf-8")
    elif format_name == "html":
        path = base_path.with_suffix(".html")
        path.write_text(render_html(result), encoding="utf-8")
    elif format_name == "pdf":
        path = base_path.with_suffix(".pdf")
        path.write_bytes(render_pdf(result))
    elif format_name == "sarif":
        path = base_path.with_suffix(".sarif")
        path.write_text(render_sarif(result), encoding="utf-8")
    elif format_name == "junit":
        path = base_path.with_suffix(".xml")
        path.write_text(render_junit(result), encoding="utf-8")
    elif format_name == "csv":
        path = base_path.with_suffix(".csv")
        path.write_text(render_csv(result), encoding="utf-8")
    else:
        raise ValueError(f"unsupported report format: {format_name}")

    return ok_response(
        f"Exported {format_name} report to {path}.", data={"path": str(path), "format": format_name}
    )
