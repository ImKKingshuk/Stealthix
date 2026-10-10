from __future__ import annotations

import argparse
import sys

from stealthix.headless import (
    HeadlessUsageError,
    emit_result,
    initialize_runtime,
    run_benchmark_cmd,
    run_crawl,
    run_distributed,
    run_extract,
    run_impact,
    run_proxy_workspace,
    run_recon,
    run_scan,
    run_support,
    run_template,
    run_workflow,
)
from stealthix.launcher import launch_tui
from stealthix_headless_cli._parser import build_parser
from stealthix_headless_cli.runtime import dispatch_cli


def cli(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = build_parser()
    args = parser.parse_args(argv)
    return dispatch_cli(
        args,
        parser,
        launch_tui=launch_tui,
        initialize_runtime=initialize_runtime,
        run_scan=run_scan,
        run_crawl=run_crawl,
        run_extract=run_extract,
        run_recon=run_recon,
        run_support=run_support,
        run_workflow=run_workflow,
        run_proxy_workspace=run_proxy_workspace,
        run_impact=run_impact,
        run_template=run_template,
        run_distributed=run_distributed,
        run_benchmark=run_benchmark_cmd,
        emit_result=emit_result,
        usage_error_cls=HeadlessUsageError,
    )


if __name__ == "__main__":
    raise SystemExit(cli())
