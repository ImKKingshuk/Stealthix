import pytest


def test_scan_exit_code_when_findings_exist(monkeypatch, capsys):
    from stealthix.core.models import Finding
    from stealthix_headless_cli import main as cli_main

    class FakeEngine:
        def __init__(self, _session):
            pass

        def detect(self):
            return type(
                "R",
                (),
                {
                    "target": "http://example.com",
                    "findings": [Finding(kind="sqli", target="x", details={})],
                    "metadata": {},
                },
            )()

    monkeypatch.setattr("stealthix.headless.Engine", FakeEngine)
    code = cli_main.cli(["scan", "-u", "http://example.com", "--report", "json"])
    _ = capsys.readouterr()
    assert code == 1


def test_launch_tui_invokes_rust_bridge(monkeypatch):
    from stealthix import launcher

    seen: dict[str, object] = {}

    def fake_run_tui(callback):
        seen["response"] = callback("app.init", {})

    monkeypatch.setattr(
        launcher,
        "initialize_runtime",
        lambda config_path, log_level: (
            object(),
            {"base_url": config_path, "verify_tls": True, "log_level": log_level},
        ),
    )
    monkeypatch.setattr(launcher, "load_rust_core", lambda: {"run_tui": fake_run_tui})

    code = launcher.launch_tui("config.yaml", "DEBUG")
    assert code == 0
    assert isinstance(seen["response"], dict)
    assert seen["response"]["ok"] is True
    assert "config.yaml" in seen["response"]["data_json"]


def test_new_cli_routes_to_rust_tui_by_default(monkeypatch):
    from stealthix_headless_cli import main as cli_main

    called: dict[str, object] = {"count": 0}

    def fake_launch_tui(config_path: str | None = None, log_level: str = "INFO") -> int:
        called["count"] += 1
        called["config_path"] = config_path
        called["log_level"] = log_level
        return 0

    monkeypatch.setattr(cli_main, "launch_tui", fake_launch_tui)
    code = cli_main.cli([])
    assert code == 0
    assert called["count"] == 1
    assert called["config_path"] is None
    assert called["log_level"] == "INFO"


def test_new_cli_passes_root_tui_bootstrap_args(monkeypatch):
    from stealthix_headless_cli import main as cli_main

    called: dict[str, object] = {}

    def fake_launch_tui(config_path: str | None = None, log_level: str = "INFO") -> int:
        called["config_path"] = config_path
        called["log_level"] = log_level
        return 0

    monkeypatch.setattr(cli_main, "launch_tui", fake_launch_tui)
    code = cli_main.cli(["--config", "config.yaml", "--log-level", "DEBUG"])
    assert code == 0
    assert called == {"config_path": "config.yaml", "log_level": "DEBUG"}


def test_new_cli_flag_shows_cli_help(monkeypatch, capsys):
    from stealthix_headless_cli import main as cli_main

    monkeypatch.setattr(
        cli_main,
        "launch_tui",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("should not launch tui")),
    )
    code = cli_main.cli(["--cli"])
    captured = capsys.readouterr()
    assert code == 0
    assert "crawl" in captured.out
    assert "scan" in captured.out


def test_new_cli_rejects_legacy_headless_flag():
    from stealthix_headless_cli import main as cli_main

    with pytest.raises(SystemExit) as exc:
        cli_main.cli(["--headless", "-u", "http://example.com"])
    assert exc.value.code == 2
