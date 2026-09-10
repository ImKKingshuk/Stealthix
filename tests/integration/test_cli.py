import json

from stealthix.core.checkpoint import CheckpointManager
from stealthix.core.engine import Finding, ScanResult
from stealthix.core.session import ScanSession, SessionConfig


def test_cli_json_output(monkeypatch, capsys):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[Finding(kind="sqli", target="t")]
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(["scan", "-u", "http://example.com", "--report", "json"])
    captured = capsys.readouterr()
    assert code == 1
    assert '"target": "http://example.com"' in captured.out
    assert '"semantic": "findings"' in captured.out


def test_cli_pdf_output(monkeypatch, tmp_path):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[Finding(kind="sqli", target="t")]
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    output = tmp_path / "report.pdf"
    from stealthix_headless_cli import main as cli_main

    cli_main.cli(["scan", "-u", "http://example.com", "--report", "pdf", "--output", str(output)])
    assert output.read_bytes().startswith(b"%PDF")


def test_cli_sarif_and_junit_outputs(monkeypatch, tmp_path):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url,
                findings=[Finding(kind="sqli", target="http://example.com?id=1")],
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    sarif_output = tmp_path / "report.sarif"
    junit_output = tmp_path / "report.xml"
    from stealthix_headless_cli import main as cli_main

    cli_main.cli(
        ["scan", "-u", "http://example.com", "--report", "sarif", "--output", str(sarif_output)]
    )
    cli_main.cli(
        ["scan", "-u", "http://example.com", "--report", "junit", "--output", str(junit_output)]
    )
    assert '"version": "2.1.0"' in sarif_output.read_text(encoding="utf-8")
    assert "<testsuite" in junit_output.read_text(encoding="utf-8")


def test_cli_version_flag(capsys):
    from stealthix import __version__
    from stealthix_headless_cli import main as cli_main

    try:
        cli_main.cli(["--version"])
    except SystemExit as exc:
        assert exc.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_cli_scan_crawl_routes_to_site_scan(monkeypatch, capsys):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def scan_site(self, *_args, **_kwargs):
            return ScanResult(
                target=self.session.config.base_url,
                findings=[Finding(kind="sqli", target="t")],
                metadata={"site_scan": True},
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    cli_main.cli(["scan", "-u", "http://example.com", "--crawl", "--report", "json"])
    captured = capsys.readouterr()
    assert '"site_scan": true' in captured.out


def test_cli_crawl_outputs_discovery_json(monkeypatch, capsys):
    class DummySpider:
        def __init__(self, session, *, options):
            self.session = session
            self.options = options

        def crawl(self, start_url=None):
            return {
                "base_url": start_url,
                "target_count": 3,
                "targets": [{"url": start_url + "/1"}],
            }

    monkeypatch.setattr("stealthix.headless.Spider", DummySpider)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(["crawl", "-u", "http://example.com", "--depth", "1"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"target_count": 3' in captured.out


def test_cli_scan_url_file_routes_to_bulk_scan(monkeypatch, capsys, tmp_path):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def scan_list(self, urls):
            assert urls == ["http://example.com/a?id=1", "http://example.com/b?id=2"]
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"multi_target": True}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    url_file = tmp_path / "targets.txt"
    url_file.write_text("http://example.com/a?id=1\nhttp://example.com/b?id=2\n", encoding="utf-8")
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(["scan", "--url-file", str(url_file), "--report", "json"])
    captured = capsys.readouterr()
    assert code == 0
    assert '"multi_target": true' in captured.out


def test_cli_auth_flags_are_applied_to_session(monkeypatch, capsys):
    class DummyEngine:
        def __init__(self, session):
            assert session.config.auth_type == "form"
            assert session.config.auth_config["username"] == "alice"
            assert session.config.auth_config["login_url"] == "/login"
            assert session.config.auth_config["csrf_field"] == "csrf_token"
            self.session = session

        def detect(self):
            return ScanResult(target=self.session.config.base_url, findings=[], metadata={})

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "-u",
            "http://example.com",
            "--auth-type",
            "form",
            "--auth-user",
            "alice",
            "--auth-pass",
            "pw",
            "--auth-login-url",
            "/login",
            "--csrf-field",
            "csrf_token",
            "--report",
            "json",
        ]
    )
    assert code == 0


def test_cli_workflow_import_hints_and_intruder(capsys, tmp_path):
    from stealthix_headless_cli import main as cli_main

    raw = (
        "POST /search?q=§term§ HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "id=42&name=§term§"
    )
    raw_file = tmp_path / "request.txt"
    raw_file.write_text(raw, encoding="utf-8")

    code = cli_main.cli(["--cli", "workflow", "import", "--raw-file", str(raw_file)])
    captured = capsys.readouterr()
    assert code == 0
    assert '"url": "http://example.com/search?q=§term§"' in captured.out

    code = cli_main.cli(["--cli", "workflow", "hints", "--raw-file", str(raw_file)])
    captured = capsys.readouterr()
    assert code == 0
    assert '"location": "query"' in captured.out

    code = cli_main.cli(
        [
            "--cli",
            "workflow",
            "intruder",
            "--raw-file",
            str(raw_file),
            "--payload",
            "term=alice",
            "--payload",
            "term=bob",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"count": 2' in captured.out
    assert "alice" in captured.out


def test_cli_proxy_workspace_routes_to_runtime_handler(capsys, tmp_path):
    from types import SimpleNamespace

    from stealthix_headless_cli._parser import build_parser
    from stealthix_headless_cli.runtime import dispatch_cli

    raw_file = tmp_path / "request.txt"
    raw_file.write_text(
        "POST /login HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
        "user=alice&id=42",
        encoding="utf-8",
    )
    workspace = tmp_path / "proxy-workspace"
    parser = build_parser()
    args = parser.parse_args(
        [
            "--cli",
            "proxy",
            "import",
            "--workspace",
            str(workspace),
            "--raw-file",
            str(raw_file),
            "--tag",
            "auth",
        ]
    )
    called = {}

    def run_proxy_workspace(proxy_args):
        called["workspace"] = proxy_args.workspace
        called["raw_file"] = proxy_args.raw_file
        called["tag"] = proxy_args.tag
        return SimpleNamespace(
            exit_code=0,
            rendered=json.dumps({"imported": 1, "workspace": proxy_args.workspace}),
        )

    def emit_result(result, output):
        print(result.rendered)

    code = dispatch_cli(
        args,
        parser,
        launch_tui=lambda *_args: 1,
        initialize_runtime=lambda *_args: (None, {}),
        run_scan=lambda *_args: None,
        run_crawl=lambda *_args: None,
        run_extract=lambda *_args: None,
        run_recon=lambda *_args: None,
        run_support=lambda *_args: None,
        run_workflow=lambda *_args: None,
        run_proxy_workspace=run_proxy_workspace,
        run_impact=lambda *_args: None,
        run_template=lambda *_args: None,
        emit_result=emit_result,
        usage_error_cls=ValueError,
    )
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert code == 0
    assert payload["imported"] == 1
    assert called == {
        "workspace": str(workspace),
        "raw_file": str(raw_file),
        "tag": ["auth"],
    }


def test_cli_template_requests_and_eval(capsys, tmp_path):
    from stealthix_headless_cli import main as cli_main

    template = tmp_path / "template.yaml"
    template.write_text(
        """
id: demo
http:
  - method: GET
    path: ["{{BaseURL}}/version"]
    matchers:
      - type: status
        status: [200]
      - type: word
        words: ["Stealthix"]
    extractors:
      - type: regex
        name: version
        regex: ["version=([0-9.]+)"]
        group: 1
""",
        encoding="utf-8",
    )

    code = cli_main.cli(
        [
            "--cli",
            "template",
            "requests",
            "--template",
            str(template),
            "--base-url",
            "https://example.com",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"url": "https://example.com/version"' in captured.out

    code = cli_main.cli(
        [
            "--cli",
            "template",
            "eval",
            "--template",
            str(template),
            "--status",
            "200",
            "--body",
            "Stealthix version=1.2.3",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"matched": true' in captured.out
    assert '"value": "1.2.3"' in captured.out


def test_cli_proxy_workspace_import_search_export(capsys, tmp_path):
    from stealthix_headless_cli import main as cli_main

    workspace = tmp_path / "proxy-workspace"
    raw = "GET /items?id=42 HTTP/1.1\r\nHost: example.com\r\n\r\n"
    raw_file = tmp_path / "request.txt"
    raw_file.write_text(raw, encoding="utf-8")

    code = cli_main.cli(
        [
            "--cli",
            "proxy",
            "import",
            "--workspace",
            str(workspace),
            "--raw-file",
            str(raw_file),
            "--tag",
            "triage",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"imported": 1' in captured.out
    assert (workspace / "history.jsonl").exists()

    code = cli_main.cli(
        [
            "--cli",
            "proxy",
            "search",
            "--workspace",
            str(workspace),
            "--query",
            "id=42",
            "--tag",
            "triage",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"count": 1' in captured.out

    code = cli_main.cli(
        ["--cli", "proxy", "export", "--workspace", str(workspace), "--format", "har"]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"creator"' in captured.out


def test_cli_impact_plan_and_gated_execute(monkeypatch, capsys):
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "--cli",
            "impact",
            "plan",
            "-u",
            "http://example.com/?id=1",
            "--dbms",
            "mssql",
            "--operation",
            "os-command",
            "--command",
            "whoami",
            "--operator",
            "alice",
            "--reason",
            "ticket-1",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"operation": "os_command"' in captured.out
    assert "xp_cmdshell" in captured.out

    code = cli_main.cli(
        [
            "--cli",
            "impact",
            "execute",
            "-u",
            "http://example.com/?id=1",
            "--dbms",
            "mssql",
            "--operation",
            "os-command",
            "--command",
            "whoami",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"executed": false' in captured.out
    assert "explicit allow flag" in captured.out

    monkeypatch.setattr(
        "stealthix.impact.executor.execute_command",
        lambda _session, command: {
            "success": True,
            "output": f"ran {command}",
            "responses": [],
            "warnings": [],
        },
    )
    code = cli_main.cli(
        [
            "--cli",
            "impact",
            "execute",
            "-u",
            "http://example.com/?id=1",
            "--dbms",
            "mssql",
            "--operation",
            "os-command",
            "--command",
            "whoami",
            "--allow-os-command",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"executed": true' in captured.out
    assert "ran whoami" in captured.out


def test_cli_can_load_and_save_session(monkeypatch, capsys, tmp_path):
    from stealthix.core.session import ScanSession, SessionConfig

    loaded_session = ScanSession(
        SessionConfig(base_url="http://example.com", auth_type="bearer", auth_token="token-1"),
        metadata={"saved": True},
    )
    session_load = tmp_path / "saved-session.json"
    session_save = tmp_path / "saved-output.json"
    loaded_session.save(str(session_load))

    class DummyEngine:
        def __init__(self, session):
            assert session.config.base_url == "http://example.com"
            assert session.config.auth_token == "token-1"
            self.session = session

        def detect(self):
            self.session.metadata["completed"] = True
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"completed": True}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "--session-load",
            str(session_load),
            "--session-save",
            str(session_save),
            "--report",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert session_save.exists()
    persisted = ScanSession.load(str(session_save))
    assert persisted.metadata["completed"] is True
    assert '"completed": true' in captured.out


def test_cli_scan_accepts_api_schema_without_url(monkeypatch, capsys, tmp_path):
    schema_path = tmp_path / "openapi.yaml"
    schema_path.write_text(
        """
openapi: 3.0.0
servers:
  - url: https://api.example.test
paths:
  /users:
    get: {}
""",
        encoding="utf-8",
    )

    class DummyEngine:
        def __init__(self, session):
            assert session.config.base_url == "https://api.example.test"
            assert session.config.api_schema == str(schema_path)
            assert session.config.api_schema_format == "openapi"
            assert session.config.api_header_params == ["X-Tenant"]
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"phase7": "api"}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "--api-schema",
            str(schema_path),
            "--api-schema-format",
            "openapi",
            "--api-header-param",
            "X-Tenant",
            "--report",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"phase7": "api"' in captured.out


def test_cli_scan_accepts_ws_url_without_http_url(monkeypatch, capsys):
    class DummyEngine:
        def __init__(self, session):
            assert session.config.base_url == "wss://socket.example.test/ws"
            assert session.config.ws_url == "wss://socket.example.test/ws"
            assert session.config.ws_messages == ['{"action":"ping"}']
            assert session.config.ws_headers == {"X-WS": "1"}
            assert session.config.ws_subprotocols == ["graphql-ws"]
            assert session.config.ws_timeout == 9.0
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"phase7": "websocket"}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "--ws-url",
            "wss://socket.example.test/ws",
            "--ws-message",
            '{"action":"ping"}',
            "--ws-header",
            "X-WS: 1",
            "--ws-subprotocol",
            "graphql-ws",
            "--ws-timeout",
            "9",
            "--report",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"phase7": "websocket"' in captured.out


def test_cli_tamper_flags_are_applied_to_session(monkeypatch, capsys):
    class DummyEngine:
        def __init__(self, session):
            assert session.config.tamper_pipeline == ["space2comment", "xforwardedfor"]
            assert session.config.tamper_auto is False
            assert session.config.tamper_retry_budget == 4
            self.session = session

        def detect(self):
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"phase8": "tamper"}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "-u",
            "http://example.com",
            "--tamper",
            "space2comment",
            "--tamper",
            "xforwardedfor",
            "--no-tamper-auto",
            "--tamper-retry-budget",
            "4",
            "--report",
            "json",
        ]
    )
    captured = capsys.readouterr()
    assert code == 0
    assert '"phase8": "tamper"' in captured.out


def test_cli_resume_uses_checkpoint_mode_and_session(monkeypatch, capsys, tmp_path):
    session = ScanSession(
        SessionConfig(base_url="http://checkpoint.example"), metadata={"saved": True}
    )
    manager = CheckpointManager(tmp_path / "resume.stx", interval_seconds=0)
    payload = manager.build_payload(
        session,
        mode="scan_list",
        status="running",
        state={"findings": [], "completed_target_keys": [], "per_target_results": []},
        input_context={
            "specs": ["http://checkpoint.example/a?id=1", "http://checkpoint.example/b?id=2"]
        },
    )
    manager.save_payload(payload, force=True)

    class DummyEngine:
        def __init__(self, current_session):
            assert current_session.config.base_url == "http://checkpoint.example"
            self.session = current_session

        def scan_list(self, urls):
            assert urls == ["http://checkpoint.example/a?id=1", "http://checkpoint.example/b?id=2"]
            return ScanResult(
                target=self.session.config.base_url, findings=[], metadata={"phase9": "resume"}
            )

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(["scan", "--resume", str(tmp_path / "resume.stx"), "--report", "json"])
    captured = capsys.readouterr()

    assert code == 0
    assert '"phase9": "resume"' in captured.out
    assert '"resumed": true' in captured.out


def test_cli_scan_error_writes_checkpoint_and_returns_exit_code_2(monkeypatch, tmp_path):
    class DummyEngine:
        def __init__(self, session):
            self.session = session

        def detect(self):
            raise RuntimeError("boom")

    monkeypatch.setattr("stealthix.headless.Engine", DummyEngine)
    checkpoint = tmp_path / "error.stx"
    from stealthix_headless_cli import main as cli_main

    code = cli_main.cli(
        [
            "scan",
            "-u",
            "http://example.com",
            "--checkpoint-file",
            str(checkpoint),
            "--checkpoint-interval",
            "1",
            "--report",
            "json",
        ]
    )

    payload = json.loads(checkpoint.read_text(encoding="utf-8"))
    assert code == 2
    assert payload["status"] == "error"
    assert payload["error"]["message"] == "boom"
