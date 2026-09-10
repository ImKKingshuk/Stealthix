import json

import pytest

from stealthix_headless_cli import main as cli_main


def test_cli_headless_extract_enum_dbs(monkeypatch, capsys):
    monkeypatch.setattr("stealthix.headless.apply_plugin", lambda _session: None)
    monkeypatch.setattr(
        "stealthix.headless.enumerate_databases", lambda _session: {"databases": ["db1", "db2"]}
    )
    code = cli_main.cli(["extract", "enum-dbs", "-u", "http://example.com", "--dbms", "mysql"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"databases"' in captured.out


def test_cli_headless_extract_dump_requires_columns(monkeypatch):
    monkeypatch.setattr("stealthix.headless.apply_plugin", lambda _session: None)
    try:
        cli_main.cli(["extract", "dump", "-u", "http://example.com", "-T", "t", "--dbms", "mysql"])
    except SystemExit as exc:
        assert exc.code == 2


def test_cli_headless_extract_hashes(monkeypatch, capsys):
    monkeypatch.setattr("stealthix.headless.apply_plugin", lambda _session: None)
    monkeypatch.setattr(
        "stealthix.headless.extract_hashes", lambda _session: {"hashes": ["abc123"]}
    )
    code = cli_main.cli(["extract", "hashes", "-u", "http://example.com", "--dbms", "mysql"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"hashes"' in captured.out


def test_cli_support_json_output(capsys):
    code = cli_main.cli(["support", "--format", "json", "--dbms", "mysql"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["platform_confidence"][0]["platform"] == "macos"
    assert payload["runtime_capabilities"]["oob"][0]["name"] == "dns_callbacks"
    assert payload["dbms"][0]["name"] == "mysql"
    assert payload["dbms"][0]["support_depth"] == "rich"
    assert payload["dbms"][0]["oob"]["dns_callbacks"] == "partial"
    assert payload["dbms"][0]["extraction"]["dump"] == "supported"


def test_cli_extract_allows_heuristic_mongodb_enum_dbs(monkeypatch, capsys):
    monkeypatch.setattr("stealthix.headless.apply_plugin", lambda _session: None)
    monkeypatch.setattr(
        "stealthix.headless.enumerate_databases", lambda _session: {"databases": ["app", "audit"]}
    )

    code = cli_main.cli(["extract", "enum-dbs", "-u", "http://example.com", "--dbms", "mongodb"])

    captured = capsys.readouterr()
    assert code == 0
    assert '"app"' in captured.out
