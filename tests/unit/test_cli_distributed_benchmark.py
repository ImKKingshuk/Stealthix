from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from stealthix_headless_cli._parser import build_parser
from stealthix_headless_cli.main import cli


def test_cli_parser_benchmark_subcommands() -> None:
    parser = build_parser()

    # Manifest
    args_manifest = parser.parse_args(["benchmark", "manifest"])
    assert args_manifest.command == "benchmark"
    assert args_manifest.benchmark_action == "manifest"

    # Summary
    args_summary = parser.parse_args(["benchmark", "summary"])
    assert args_summary.command == "benchmark"
    assert args_summary.benchmark_action == "summary"

    # Run
    args_run = parser.parse_args(["benchmark", "run", "--target-url", "http://test.local"])
    assert args_run.command == "benchmark"
    assert args_run.benchmark_action == "run"
    assert args_run.target_url == "http://test.local"


def test_cli_parser_distributed_subcommands() -> None:
    parser = build_parser()

    # Coordinator
    args_coord = parser.parse_args(
        ["distributed", "coordinator", "--url-file", "urls.txt", "--redis-host", "127.0.0.1", "--workers", "8"]
    )
    assert args_coord.command == "distributed"
    assert args_coord.distributed_action == "coordinator"
    assert args_coord.url_file == "urls.txt"
    assert args_coord.redis_host == "127.0.0.1"
    assert args_coord.workers == 8

    # Worker
    args_worker = parser.parse_args(
        ["distributed", "worker", "--redis-host", "10.0.0.1", "--redis-port", "6380", "--worker-id", "w1"]
    )
    assert args_worker.command == "distributed"
    assert args_worker.distributed_action == "worker"
    assert args_worker.redis_host == "10.0.0.1"
    assert args_worker.redis_port == 6380
    assert args_worker.worker_id == "w1"


def test_cli_benchmark_manifest_execution(capsys) -> None:
    code = cli(["--cli", "benchmark", "manifest"])
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["manifest_id"] == "stealthix.phase1.vulnerable-foundation"
    assert len(payload["scenarios"]) > 0


def test_cli_benchmark_summary_execution(capsys) -> None:
    code = cli(["--cli", "benchmark", "summary"])
    assert code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert "scenario_count" in payload
    assert "coverage" in payload
    assert "families" in payload


def test_cli_distributed_worker_execution() -> None:
    with patch("stealthix.headless.run_worker") as mock_run_worker:
        code = cli(["--cli", "distributed", "worker", "--redis-host", "mock-redis", "--redis-port", "6379"])
        assert code == 0
        mock_run_worker.assert_called_once_with(redis_host="mock-redis", redis_port=6379)
