from __future__ import annotations

import argparse

from stealthix import __version__
from stealthix.detection.rest_api import API_METHODS


def _add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-u", "--url")
    parser.add_argument("--config")
    parser.add_argument("--proxy")
    parser.add_argument("--header", action="append", default=[])
    parser.add_argument("--cookie", action="append", default=[])
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--verify-tls", action="store_true", default=True)
    parser.add_argument("--no-verify-tls", action="store_false", dest="verify_tls")
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--technique", help="Attack technique (B/E/U/T/S)")
    parser.add_argument("--dbms")
    parser.add_argument("--risk", type=int, choices=[1, 2, 3], default=1)
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4, 5], default=1)
    parser.add_argument("--threads", type=int, help="Concurrent detection workers (default: 5)")
    parser.add_argument(
        "--param", action="append", default=[], help="Test a specific parameter (repeatable)"
    )
    parser.add_argument("--test-all-params", action="store_true")
    parser.add_argument("--batch", action="store_true")
    parser.add_argument("--wizard", action="store_true")
    parser.add_argument("--session-load", help="Load a saved scan session before running")
    parser.add_argument("--session-save", help="Persist session state after the command completes")
    parser.add_argument("--resume", help="Resume a scan from a checkpoint file")
    parser.add_argument(
        "--checkpoint-file", help="Path to a checkpoint file to write during the scan"
    )
    parser.add_argument(
        "--checkpoint-interval",
        type=float,
        default=0.0,
        help="Checkpoint save interval in seconds (0 disables periodic checkpointing)",
    )
    parser.add_argument(
        "--auth-type",
        choices=["bearer", "jwt", "token", "basic", "digest", "ntlm", "form", "script"],
    )
    parser.add_argument("--auth-user", help="Authentication username")
    parser.add_argument("--auth-pass", help="Authentication password")
    parser.add_argument("--auth-token", help="Bearer/JWT token value")
    parser.add_argument("--auth-login-url", help="Login page or form submission URL for form auth")
    parser.add_argument("--auth-user-field", help="Username field name for form auth")
    parser.add_argument("--auth-pass-field", help="Password field name for form auth")
    parser.add_argument(
        "--auth-extra-field", action="append", default=[], help="Extra auth form field as key=value"
    )
    parser.add_argument("--auth-refresh-url", help="Token refresh endpoint for bearer/JWT auth")
    parser.add_argument("--auth-refresh-method", choices=["GET", "POST"], default="POST")
    parser.add_argument("--auth-refresh-body-format", choices=["form", "json"], default="json")
    parser.add_argument(
        "--auth-refresh-body", action="append", default=[], help="Refresh body field as key=value"
    )
    parser.add_argument(
        "--auth-token-path", help="Dot path for access token inside refresh JSON response"
    )
    parser.add_argument(
        "--auth-header", default="Authorization", help="Header name for bearer token auth"
    )
    parser.add_argument(
        "--auth-scheme", default="Bearer", help="Header scheme for bearer token auth"
    )
    parser.add_argument("--auth-script", help="Path to a Python auth automation script")
    parser.add_argument(
        "--auth-success-indicator", help="Response text that indicates auth succeeded"
    )
    parser.add_argument("--auth-failure-indicator", help="Response text that indicates auth failed")
    parser.add_argument("--auth-verify-url", help="URL to fetch after login to verify the session")
    parser.add_argument(
        "--csrf-url", help="URL used to fetch CSRF tokens before authenticated POST requests"
    )
    parser.add_argument(
        "--csrf-field", help="Explicit CSRF field name to inject into POST requests"
    )
    parser.add_argument("--method", choices=list(API_METHODS), default="GET")
    parser.add_argument(
        "--api-schema", help="Path to an OpenAPI/Swagger document or Postman collection"
    )
    parser.add_argument(
        "--api-schema-format", choices=["auto", "openapi", "postman"], default="auto"
    )
    parser.add_argument(
        "--api-base-url", help="Base URL override for imported API schema operations"
    )
    parser.add_argument(
        "--api-header-param",
        action="append",
        default=[],
        help="Header name to treat as an injectable API parameter",
    )
    parser.add_argument("--ws-url", help="WebSocket endpoint to probe (ws:// or wss://)")
    parser.add_argument(
        "--ws-message",
        action="append",
        default=[],
        help="Baseline WebSocket message to mutate and test",
    )
    parser.add_argument(
        "--ws-header", action="append", default=[], help="WebSocket handshake header as Name: Value"
    )
    parser.add_argument(
        "--ws-subprotocol", action="append", default=[], help="WebSocket subprotocol to request"
    )
    parser.add_argument(
        "--ws-timeout", type=float, default=10.0, help="WebSocket connect/read timeout in seconds"
    )
    parser.add_argument(
        "--tamper",
        action="append",
        default=[],
        help="Append a tamper script to the payload pipeline",
    )
    parser.add_argument(
        "--no-tamper-auto",
        dest="tamper_auto",
        action="store_false",
        default=True,
        help="Disable automatic WAF-aware tamper selection",
    )
    parser.add_argument(
        "--tamper-retry-budget",
        type=int,
        default=3,
        help="Maximum adaptive tamper retry attempts for blocked requests",
    )


def _add_crawl_options(parser: argparse.ArgumentParser, *, prefix: str = "crawl_") -> None:
    option_prefix = f"{prefix[:-1].replace('_', '-')}-" if prefix else ""
    parser.add_argument(f"--{option_prefix}depth", dest=f"{prefix}depth", type=int, default=2)
    parser.add_argument(
        f"--{option_prefix}max-pages", dest=f"{prefix}max_pages", type=int, default=50
    )
    parser.add_argument(
        f"--{option_prefix}scope",
        dest=f"{prefix}scope",
        choices=["host", "domain", "any"],
        default="host",
    )
    parser.add_argument(
        f"--no-{option_prefix}robots",
        dest=f"{prefix}parse_robots",
        action="store_false",
        default=True,
    )
    parser.add_argument(
        f"--no-{option_prefix}sitemap",
        dest=f"{prefix}parse_sitemap",
        action="store_false",
        default=True,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stealthix", description="Stealthix launcher for the Rust TUI and headless CLI"
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--config", help="Path to YAML/JSON config file for the default TUI launch path"
    )
    parser.add_argument(
        "--log-level", default="INFO", help="Logging level for the default TUI launch path"
    )
    parser.add_argument(
        "--cli",
        "--headless",
        dest="cli",
        action="store_true",
        help="Use the explicit headless CLI surface instead of the default Rust TUI",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="Run a headless scan")
    _add_common_options(scan)
    _add_crawl_options(scan)
    scan.add_argument(
        "--crawl", action="store_true", help="Crawl the site first and scan discovered URLs/forms"
    )
    scan.add_argument("--url-file", help="Path to a newline-delimited file of URLs to scan")
    scan.add_argument(
        "--report",
        choices=["html", "json", "markdown", "pdf", "sarif", "junit", "csv"],
        default="json",
    )
    scan.add_argument("--output")
    scan.add_argument("--distributed", action="store_true", help="Enable distributed worker mode")
    scan.add_argument("--redis-host", default="localhost", help="Redis host for distributed mode")
    scan.add_argument(
        "--redis-port", type=int, default=6379, help="Redis port for distributed mode"
    )
    scan.add_argument("--workers", type=int, default=4, help="Number of worker processes")
    scan.add_argument("--chunk-size", type=int, default=25, help="Targets per task chunk")
    scan.add_argument("--worker-mode", action="store_true", help="Run as worker process only")

    crawl = subparsers.add_parser("crawl", help="Discover URLs and forms from a target site")
    _add_common_options(crawl)
    _add_crawl_options(crawl, prefix="")
    crawl.add_argument("--output")

    common_extract = argparse.ArgumentParser(add_help=False)
    _add_common_options(common_extract)
    common_extract.add_argument("--output")
    common_extract.add_argument("-D", "--database")
    common_extract.add_argument("-T", "--table")
    common_extract.add_argument("-C", "--column", action="append", default=[])

    extract = subparsers.add_parser("extract", help="Run headless extraction helpers")
    extract_sub = extract.add_subparsers(dest="extract_action")
    extract_sub.required = True

    extract_sub.add_parser(
        "enum-dbs", parents=[common_extract], help="Enumerate databases"
    ).set_defaults(extract_action="enum_dbs")
    extract_sub.add_parser(
        "enum-tables", parents=[common_extract], help="Enumerate tables"
    ).set_defaults(extract_action="enum_tables")
    extract_sub.add_parser(
        "enum-columns", parents=[common_extract], help="Enumerate columns"
    ).set_defaults(extract_action="enum_columns")
    extract_sub.add_parser("dump", parents=[common_extract], help="Dump a table").set_defaults(
        extract_action="dump"
    )
    read_file = extract_sub.add_parser("read-file", parents=[common_extract], help="Read a file")
    read_file.add_argument("--path", required=True)
    read_file.set_defaults(extract_action="read_file")
    os_cmd = extract_sub.add_parser(
        "os-cmd", parents=[common_extract], help="Execute an OS command"
    )
    os_cmd.add_argument("--command", dest="shell_command", required=True)
    os_cmd.set_defaults(extract_action="os_cmd")
    extract_sub.add_parser(
        "hashes", parents=[common_extract], help="Extract password hashes"
    ).set_defaults(extract_action="hashes")

    support = subparsers.add_parser("support", help="Show the current support matrix")
    support.add_argument("--format", choices=["table", "json", "markdown"], default="table")
    support.add_argument("--dbms", help="Filter the support matrix to a single DBMS")

    recon = subparsers.add_parser(
        "recon", help="Run reconnaissance (technology detection and endpoint discovery)"
    )
    recon_sub = recon.add_subparsers(dest="recon_action")
    recon_sub.required = True

    tech = recon_sub.add_parser("tech", help="Detect technology stack")
    tech.add_argument("-u", "--url", required=True, help="Target URL")
    tech.add_argument("--output", help="Output file path")
    tech.add_argument("--format", choices=["json", "text"], default="text", help="Output format")
    tech.add_argument("--proxy", help="HTTP proxy URL")
    tech.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    tech.add_argument("--verify-tls", action="store_true", default=True)
    tech.add_argument("--no-verify-tls", action="store_false", dest="verify_tls")
    tech.set_defaults(recon_action="tech")

    endpoints = recon_sub.add_parser("endpoints", help="Discover hidden endpoints")
    endpoints.add_argument("-u", "--url", required=True, help="Target URL")
    endpoints.add_argument("--output", help="Output file path")
    endpoints.add_argument(
        "--format", choices=["json", "text"], default="text", help="Output format"
    )
    endpoints.add_argument("--wordlist", help="Path to custom wordlist file")
    endpoints.add_argument("--depth", type=int, default=2, help="Discovery depth")
    endpoints.add_argument(
        "--max-endpoints", type=int, default=100, help="Maximum endpoints to probe"
    )
    endpoints.add_argument("--proxy", help="HTTP proxy URL")
    endpoints.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    endpoints.add_argument("--verify-tls", action="store_true", default=True)
    endpoints.add_argument("--no-verify-tls", action="store_false", dest="verify_tls")
    endpoints.set_defaults(recon_action="endpoints")

    workflow = subparsers.add_parser(
        "workflow", help="Normalize, inspect, and fuzz captured HTTP requests"
    )
    workflow_sub = workflow.add_subparsers(dest="workflow_action")
    workflow_sub.required = True

    def add_request_source_options(source_parser: argparse.ArgumentParser) -> None:
        source_group = source_parser.add_mutually_exclusive_group(required=True)
        source_group.add_argument("--raw-file", help="Path to a raw HTTP request file")
        source_group.add_argument("--raw", help="Raw HTTP request text")
        source_group.add_argument("--curl", help="curl command to import")
        source_group.add_argument("--har", help="HAR file to import")

    import_req = workflow_sub.add_parser("import", help="Normalize a captured request")
    add_request_source_options(import_req)
    import_req.add_argument("--default-scheme", default="http")
    import_req.add_argument("--output")
    import_req.set_defaults(workflow_action="import")

    hints = workflow_sub.add_parser("hints", help="Generate passive injection hints")
    add_request_source_options(hints)
    hints.add_argument("--default-scheme", default="http")
    hints.add_argument("--output")
    hints.set_defaults(workflow_action="hints")

    intruder = workflow_sub.add_parser("intruder", help="Expand §marker§/{{marker}} positions")
    add_request_source_options(intruder)
    intruder.add_argument(
        "--payload",
        action="append",
        default=[],
        help="Payload assignment as marker=value. Repeat for each marker/value.",
    )
    intruder.add_argument(
        "--mode", choices=["clusterbomb", "pitchfork", "sniper"], default="clusterbomb"
    )
    intruder.add_argument("--limit", type=int)
    intruder.add_argument("--default-scheme", default="http")
    intruder.add_argument("--output")
    intruder.set_defaults(workflow_action="intruder")

    proxy = subparsers.add_parser("proxy", help="Manage local proxy workspace captures and exports")
    proxy_sub = proxy.add_subparsers(dest="proxy_action")
    proxy_sub.required = True

    proxy_import = proxy_sub.add_parser(
        "import", help="Import captured HTTP requests into a persistent workspace"
    )
    proxy_import.add_argument(
        "--workspace",
        default=".stealthix/proxy-workspace",
        help="Proxy workspace directory",
    )
    add_request_source_options(proxy_import)
    proxy_import.add_argument("--default-scheme", default="http")
    proxy_import.add_argument("--tag", action="append", default=[])
    proxy_import.add_argument("--note", default="")
    proxy_import.add_argument("--output")
    proxy_import.set_defaults(proxy_action="import")

    proxy_search = proxy_sub.add_parser("search", help="Search proxy workspace history")
    proxy_search.add_argument(
        "--workspace",
        default=".stealthix/proxy-workspace",
        help="Proxy workspace directory",
    )
    proxy_search.add_argument("--query")
    proxy_search.add_argument("--method")
    proxy_search.add_argument("--status")
    proxy_search.add_argument("--tag")
    proxy_search.add_argument("--host")
    proxy_search.add_argument("--limit", type=int)
    proxy_search.add_argument("--output")
    proxy_search.set_defaults(proxy_action="search")

    proxy_export = proxy_sub.add_parser("export", help="Export proxy workspace history")
    proxy_export.add_argument(
        "--workspace",
        default=".stealthix/proxy-workspace",
        help="Proxy workspace directory",
    )
    proxy_export.add_argument("--format", choices=["json", "jsonl", "yaml", "har"], default="json")
    proxy_export.add_argument("--output")
    proxy_export.set_defaults(proxy_action="export")

    proxy_stats = proxy_sub.add_parser("stats", help="Summarize proxy workspace history")
    proxy_stats.add_argument(
        "--workspace",
        default=".stealthix/proxy-workspace",
        help="Proxy workspace directory",
    )
    proxy_stats.add_argument("--output")
    proxy_stats.set_defaults(proxy_action="stats")

    impact = subparsers.add_parser(
        "impact", help="Plan and explicitly execute DBMS-specific file/OS/UDF impact workflows"
    )
    impact_sub = impact.add_subparsers(dest="impact_action")
    impact_sub.required = True

    impact_matrix = impact_sub.add_parser("matrix", help="Show DBMS impact capability profiles")
    impact_matrix.add_argument("--dbms")
    impact_matrix.add_argument("--output")
    impact_matrix.set_defaults(impact_action="matrix")

    common_impact = argparse.ArgumentParser(add_help=False)
    _add_common_options(common_impact)
    common_impact.add_argument(
        "--operation",
        required=True,
        choices=[
            "file-read",
            "file-write",
            "os-command",
            "udf-dropper",
            "read-file",
            "write-file",
            "os-cmd",
            "udf",
        ],
    )
    common_impact.add_argument("--path", help="Source path for file-read operations")
    common_impact.add_argument("--destination", help="Destination path for file-write operations")
    common_impact.add_argument("--content", help="Inline file content for file-write operations")
    common_impact.add_argument(
        "--content-file", help="File content source for file-write operations"
    )
    common_impact.add_argument(
        "--command", dest="impact_command", help="Command for os-command operations"
    )
    common_impact.add_argument(
        "--operator", help="Operator name or ticket/user id for audit metadata"
    )
    common_impact.add_argument("--reason", help="Authorization or change-control reason")
    common_impact.add_argument("--output")

    impact_plan = impact_sub.add_parser(
        "plan", parents=[common_impact], help="Build an operator-controlled impact plan"
    )
    impact_plan.set_defaults(impact_action="plan")

    impact_execute = impact_sub.add_parser(
        "execute",
        parents=[common_impact],
        help="Execute an impact plan only when the matching allow flag is provided",
    )
    impact_execute.add_argument("--allow-file-read", action="store_true")
    impact_execute.add_argument("--allow-file-write", action="store_true")
    impact_execute.add_argument("--allow-os-command", action="store_true")
    impact_execute.add_argument("--allow-udf-dropper", action="store_true")
    impact_execute.set_defaults(impact_action="execute")

    template = subparsers.add_parser(
        "template", help="Load and evaluate Stealthix detection templates"
    )
    template_sub = template.add_subparsers(dest="template_action")
    template_sub.required = True

    template_requests = template_sub.add_parser(
        "requests", help="Render template HTTP requests for a base URL"
    )
    template_requests.add_argument("--template", required=True, help="Template YAML/JSON path")
    template_requests.add_argument("--base-url", required=True)
    template_requests.add_argument("--allow-unsafe-methods", action="store_true")
    template_requests.add_argument("--output")
    template_requests.set_defaults(template_action="requests")

    template_eval = template_sub.add_parser(
        "eval", help="Evaluate a template against a captured response"
    )
    template_eval.add_argument("--template", required=True, help="Template YAML/JSON path")
    template_eval.add_argument("--status", type=int, required=True)
    template_eval.add_argument("--header", action="append", default=[])
    template_eval.add_argument("--body-file")
    template_eval.add_argument("--body", default="")
    template_eval.add_argument("--request-index", type=int, default=0)
    template_eval.add_argument("--allow-unsafe-methods", action="store_true")
    template_eval.add_argument("--output")
    template_eval.set_defaults(template_action="eval")

    # Distributed subcommand
    distributed = subparsers.add_parser(
        "distributed", help="Run distributed coordinator or worker processes"
    )
    dist_sub = distributed.add_subparsers(dest="distributed_action")
    dist_sub.required = True

    dist_coord = dist_sub.add_parser("coordinator", help="Run as distributed scan coordinator")
    _add_common_options(dist_coord)
    dist_coord.add_argument("--url-file", help="Path to a newline-delimited file of URLs to scan")
    dist_coord.add_argument("--redis-host", default="localhost", help="Redis host")
    dist_coord.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    dist_coord.add_argument("--workers", type=int, default=4, help="Number of worker processes")
    dist_coord.add_argument("--chunk-size", type=int, default=25, help="Targets per task chunk")
    dist_coord.add_argument(
        "--report",
        choices=["html", "json", "markdown", "pdf", "sarif", "junit", "csv"],
        default="json",
    )
    dist_coord.add_argument("--output")
    dist_coord.set_defaults(distributed_action="coordinator")

    dist_worker = dist_sub.add_parser("worker", help="Run as distributed scan worker process")
    dist_worker.add_argument("--redis-host", default="localhost", help="Redis host")
    dist_worker.add_argument("--redis-port", type=int, default=6379, help="Redis port")
    dist_worker.add_argument("--worker-id", help="Optional worker ID")
    dist_worker.set_defaults(distributed_action="worker")

    # Benchmark subcommand
    benchmark = subparsers.add_parser(
        "benchmark", help="Run or inspect Stealthix benchmark evaluation suites"
    )
    bench_sub = benchmark.add_subparsers(dest="benchmark_action")
    bench_sub.required = True

    bench_manifest = bench_sub.add_parser("manifest", help="Show or export benchmark manifest")
    bench_manifest.add_argument("--output", help="Output path for JSON manifest")
    bench_manifest.set_defaults(benchmark_action="manifest")

    bench_run = bench_sub.add_parser("run", help="Execute benchmark suite against test targets")
    bench_run.add_argument("--manifest-file", help="Path to custom benchmark manifest JSON")
    bench_run.add_argument("--target-url", help="Override target URL for benchmark scenarios")
    bench_run.add_argument("--output", help="Output path for benchmark report")
    bench_run.set_defaults(benchmark_action="run")

    bench_summary = bench_sub.add_parser(
        "summary", help="Show summary of available fixture catalog"
    )
    bench_summary.add_argument("--output", help="Output path for summary")
    bench_summary.set_defaults(benchmark_action="summary")

    return parser


__all__ = ["build_parser"]
