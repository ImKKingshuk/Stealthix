from __future__ import annotations

import argparse
from collections.abc import Callable
from typing import Any


def dispatch_cli(
    args: argparse.Namespace,
    parser: argparse.ArgumentParser,
    *,
    launch_tui: Callable[[str | None, str], int],
    initialize_runtime: Callable[[str | None, str], tuple[Any, dict[str, Any]]],
    run_scan: Callable[[Any, Any, dict[str, Any]], Any],
    run_crawl: Callable[[Any, dict[str, Any]], Any],
    run_extract: Callable[[Any, dict[str, Any]], Any],
    run_recon: Callable[[Any, dict[str, Any]], Any],
    run_support: Callable[[Any], Any],
    run_workflow: Callable[[Any], Any],
    run_proxy_workspace: Callable[[Any], Any],
    run_impact: Callable[[Any, dict[str, Any]], Any],
    run_template: Callable[[Any], Any],
    run_distributed: Callable[[Any, dict[str, Any]], Any] | None = None,
    run_benchmark: Callable[[Any], Any] | None = None,
    emit_result: Callable[[Any, str | None], None],
    usage_error_cls: type[Exception],
) -> int:
    if args.command is None:
        if args.cli:
            parser.print_help()
            return 0
        return launch_tui(args.config, args.log_level)

    try:
        if args.command == "support":
            result = run_support(args)
        elif args.command == "benchmark":
            if run_benchmark is None:
                from stealthix.headless import run_benchmark_cmd as default_bench

                run_benchmark = default_bench
            result = run_benchmark(args)
        else:
            logger, config_data = initialize_runtime(
                getattr(args, "config", None), getattr(args, "log_level", "INFO")
            )
            if args.command == "scan":
                result = run_scan(args, logger, config_data)
            elif args.command == "crawl":
                result = run_crawl(args, config_data)
            elif args.command == "recon":
                result = run_recon(args, config_data)
            elif args.command == "workflow":
                result = run_workflow(args)
            elif args.command == "proxy":
                result = run_proxy_workspace(args)
            elif args.command == "impact":
                result = run_impact(args, config_data)
            elif args.command == "template":
                result = run_template(args)
            elif args.command == "distributed":
                if run_distributed is None:
                    from stealthix.headless import run_distributed as default_dist

                    run_distributed = default_dist
                result = run_distributed(args, config_data)
            else:
                result = run_extract(args, config_data)
    except usage_error_cls as exc:
        parser.error(str(exc))
    emit_result(result, getattr(args, "output", None))
    return int(result.exit_code)


__all__ = ["dispatch_cli"]
