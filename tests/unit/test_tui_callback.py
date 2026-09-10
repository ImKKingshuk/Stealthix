import json
import time

from stealthix.core.models import Finding, ScanResult
from stealthix.tui_callback import build_tui_callback


def test_callback_profile_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("STEALTHIX_PROFILES_DIR", str(tmp_path / "profiles"))
    callback = build_tui_callback()

    save_resp = callback(
        "profile.save",
        {
            "name": "demo",
            "url": "http://example.com",
            "method": "GET",
            "risk": 1,
            "level": 1,
            "threads": 7,
            "verify_tls": True,
        },
    )
    assert save_resp["ok"] is True

    init_resp = callback("app.init", {})
    payload = json.loads(init_resp["data_json"])
    assert "demo" in payload["profiles"]

    load_resp = callback("profile.load", {"name": "demo"})
    loaded = json.loads(load_resp["data_json"])
    assert loaded["config"]["base_url"] == "http://example.com"
    assert loaded["config"]["threads"] == 7


def test_callback_app_init_includes_bootstrap_config():
    callback = build_tui_callback(
        initial_config={
            "base_url": "http://example.com",
            "method": "POST",
            "verify_tls": False,
            "threads": 9,
        }
    )

    init_resp = callback("app.init", {})
    payload = json.loads(init_resp["data_json"])
    assert payload["initial_config"]["base_url"] == "http://example.com"
    assert payload["initial_config"]["method"] == "POST"
    assert payload["initial_config"]["threads"] == 9
    assert payload["crawl_defaults"]["scope"] == "host"
    assert "form" in payload["auth_types"]
    assert payload["auth_defaults"]["scheme"] == "Bearer"
    assert payload["api_schema_formats"] == ["auto", "openapi", "postman"]
    assert payload["websocket_defaults"]["timeout"] == 10.0
    assert any(entry["name"] == "mysql" for entry in payload["support_matrix"]["dbms"])
    assert payload["support_matrix"]["platform_confidence"][0]["platform"] == "macos"


def test_callback_can_describe_supported_dbms():
    callback = build_tui_callback()

    resp = callback("dbms.describe_supported", {})
    payload = json.loads(resp["data_json"])

    assert resp["ok"] is True
    assert "json" in payload["report_formats"]
    assert payload["runtime_capabilities"]["waf"][0]["name"] == "auto_detection"
    assert any(entry["name"] == "postgresql" for entry in payload["dbms"])
    assert "sarif" in payload["report_formats"]


def test_callback_proxy_workspace_search(tmp_path):
    from stealthix.proxy import ProxyWorkspace
    from stealthix.workflows.requests import import_raw_http

    workspace = tmp_path / "proxy-workspace"
    ProxyWorkspace(workspace).capture_request(
        import_raw_http("GET /items?id=42 HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        tags=["triage"],
    )
    callback = build_tui_callback()

    resp = callback("proxy.search", {"workspace": str(workspace), "query": "id=42"})
    payload = json.loads(resp["data_json"])

    assert resp["ok"] is True
    assert payload["stats"]["record_count"] == 1
    assert payload["records"][0]["request"]["url"] == "http://example.com/items?id=42"


def test_callback_scan_job_lifecycle(monkeypatch):
    from stealthix import _tui_callback_runtime as runtime

    def fake_run_detection(self, job):
        job.estimated_total_requests = 10
        return ScanResult(
            target="http://example.com",
            findings=[Finding(kind="sqli", target="http://example.com", details={"payload": "x"})],
            metadata={"source": "test"},
        )

    monkeypatch.setattr(runtime.ScanJobStore, "_run_detection", fake_run_detection)
    callback = build_tui_callback()

    start = callback("scan.start", {"url": "http://example.com", "method": "GET"})
    assert start["ok"] is True
    job = json.loads(start["job_json"])

    final = None
    for _ in range(20):
        poll = callback("scan.poll", {"job_id": job["job_id"]})
        assert poll["ok"] is True
        payload = json.loads(poll["data_json"])
        if payload["status"] == "done":
            final = payload
            break
        time.sleep(0.01)

    assert final is not None
    assert final["finding_count"] == 1
    assert final["result"]["findings"][0]["kind"] == "sqli"
    assert final["phase"] == "Complete"


def test_callback_scan_discover_and_pause_resume(monkeypatch):
    from stealthix import _tui_callback_runtime as runtime
    from stealthix import _tui_callback_scan as scan_mod

    callback = build_tui_callback()

    monkeypatch.setattr(
        scan_mod,
        "discover_target_params",
        lambda _session: [
            type("Param", (), {"name": "id", "location": "query", "kind": "param"})(),
            type("Param", (), {"name": "user", "location": "body", "kind": "param"})(),
        ],
    )
    discover = callback("scan.discover_params", {"url": "http://example.com", "method": "GET"})
    assert discover["ok"] is True
    discovered = json.loads(discover["data_json"])
    assert [item["name"] for item in discovered["params"]] == ["id", "user"]

    def fake_run_detection(self, job):
        while not job.session.control.cancel.is_set():
            job.session.control.wait_if_paused()
            time.sleep(0.01)
        return ScanResult(target="http://example.com", findings=[], metadata={})

    monkeypatch.setattr(runtime.ScanJobStore, "_run_detection", fake_run_detection)
    start = callback("scan.start", {"url": "http://example.com", "method": "GET"})
    job = json.loads(start["job_json"])

    paused = callback("scan.pause", {"job_id": job["job_id"]})
    assert paused["ok"] is True
    assert json.loads(paused["data_json"])["status"] == "paused"

    resumed = callback("scan.resume", {"job_id": job["job_id"]})
    assert resumed["ok"] is True
    assert json.loads(resumed["data_json"])["status"] == "running"

    callback("scan.cancel", {"job_id": job["job_id"]})


def test_callback_scan_discover_passes_phase7_api_and_websocket_config(monkeypatch, tmp_path):
    from stealthix import _tui_callback_scan as scan_mod

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
    callback = build_tui_callback()

    def fake_discover(session):
        assert session.config.base_url == "https://api.example.test"
        assert session.config.api_schema == str(schema_path)
        assert session.config.api_header_params == ["X-Tenant"]
        assert session.config.ws_url == "wss://socket.example.test/ws"
        return [type("Param", (), {"name": "userId", "location": "path", "kind": "number"})()]

    monkeypatch.setattr(scan_mod, "discover_target_params", fake_discover)
    discover = callback(
        "scan.discover_params",
        {
            "api_schema": str(schema_path),
            "api_schema_format": "openapi",
            "api_header_param": "X-Tenant",
            "ws_url": "wss://socket.example.test/ws",
        },
    )

    assert discover["ok"] is True
    discovered = json.loads(discover["data_json"])
    assert discovered["params"][0]["name"] == "userId"


def test_callback_crawl_discover_returns_targets(monkeypatch):
    from stealthix import _tui_callback_scan as scan_mod

    callback = build_tui_callback()

    class FakeSpider:
        def __init__(self, session, *, options):
            self.session = session
            self.options = options

        def crawl(self, start_url=None):
            assert start_url == "http://example.com"
            return {
                "base_url": start_url,
                "target_count": 2,
                "targets": [{"url": start_url + "/a"}, {"url": start_url + "/b"}],
            }

    monkeypatch.setattr(scan_mod, "Spider", FakeSpider)
    resp = callback(
        "crawl.discover",
        {"url": "http://example.com", "method": "GET", "crawl_depth": 1, "crawl_max_pages": 5},
    )

    assert resp["ok"] is True
    assert json.loads(resp["data_json"])["target_count"] == 2


def test_callback_scan_start_accepts_crawl_targets(monkeypatch):
    from stealthix import _tui_callback_scan as scan_mod
    from stealthix._tui_runtime.jobs import ScanJob

    callback = build_tui_callback()
    captured: dict[str, object] = {}

    def fake_start(session):
        captured["session"] = session
        return ScanJob(job_id="job-1", session=session)

    monkeypatch.setattr(scan_mod.JOBS, "start", fake_start)
    resp = callback(
        "scan.start",
        {
            "url": "http://example.com",
            "method": "GET",
            "crawl": True,
            "crawl_depth": 3,
            "crawl_max_pages": 25,
            "crawl_scope": "domain",
            "crawl_targets": [
                {"url": "http://example.com/search?q=test", "method": "GET", "target_params": ["q"]}
            ],
        },
    )

    assert resp["ok"] is True
    session = captured["session"]
    assert session.metadata["crawl_targets"][0]["url"] == "http://example.com/search?q=test"
    assert session.metadata["crawl_options"]["enabled"] is True
    assert session.metadata["crawl_options"]["scope"] == "domain"


def test_callback_auth_login_and_session_roundtrip(monkeypatch, tmp_path):
    from stealthix import _tui_callback_scan as scan_mod

    callback = build_tui_callback()

    def fake_auth(session, force=True, reason=None):
        session.config.cookies["sid"] = "cookie-1"
        session.metadata["auth"] = {"authenticated": True, "reason": reason}
        return True

    monkeypatch.setattr(scan_mod, "ensure_authenticated", fake_auth)

    auth_resp = callback(
        "auth.login",
        {
            "url": "http://example.com",
            "method": "GET",
            "auth_type": "form",
            "auth_user": "alice",
            "auth_pass": "pw",
        },
    )
    auth_payload = json.loads(auth_resp["data_json"])
    assert auth_resp["ok"] is True
    assert auth_payload["auth"]["authenticated"] is True
    assert auth_payload["cookies"]["sid"] == "cookie-1"

    session_path = tmp_path / "tui-session.json"
    save_resp = callback(
        "session.save", {"path": str(session_path), "session": auth_payload["session"]}
    )
    assert save_resp["ok"] is True

    load_resp = callback("session.load", {"path": str(session_path)})
    loaded = json.loads(load_resp["data_json"])
    assert loaded["config"]["auth_type"] == "form"
    assert loaded["config"]["cookies"]["sid"] == "cookie-1"


def test_callback_extract_and_report_actions(monkeypatch, tmp_path):
    from stealthix import _tui_callback_extract as extract_mod
    from stealthix import _tui_callback_reports as report_mod

    callback = build_tui_callback()
    monkeypatch.setattr(extract_mod, "apply_plugin", lambda session: None)
    monkeypatch.setattr(extract_mod, "enumerate_databases", lambda session: {"databases": ["app"]})
    monkeypatch.setenv("STEALTHIX_OUTPUT_DIR", str(tmp_path))

    session_payload = {
        "config": {
            "base_url": "http://example.com",
            "method": "GET",
            "verify_tls": True,
            "dbms": "mysql",
        },
        "metadata": {},
        "history": [],
        "creds": {},
    }
    extract_resp = callback("extract.enum_databases", {"session": session_payload})
    assert extract_resp["ok"] is True
    assert json.loads(extract_resp["data_json"]) == {"databases": ["app"]}

    export_resp = callback(
        "extract.export_dump",
        {
            "session": session_payload,
            "table": "users",
            "format": "json",
            "dump": {"rows": [{"username": "admin"}]},
        },
    )
    assert export_resp["ok"] is True
    export_data = json.loads(export_resp["data_json"])
    assert export_data["path"].endswith(".json")

    monkeypatch.setattr(
        report_mod, "render_json", lambda result: json.dumps({"target": result.target})
    )
    monkeypatch.setattr(
        report_mod,
        "render_sarif",
        lambda result: json.dumps({"target": result.target, "version": "2.1.0"}),
    )
    report_resp = callback(
        "report.export",
        {
            "format": "json",
            "result": {"target": "http://example.com", "findings": [], "metadata": {}},
        },
    )
    assert report_resp["ok"] is True
    report_data = json.loads(report_resp["data_json"])
    assert report_data["path"].endswith(".json")

    sarif_resp = callback(
        "report.export",
        {
            "format": "sarif",
            "result": {"target": "http://example.com", "findings": [], "metadata": {}},
        },
    )
    assert sarif_resp["ok"] is True
    assert json.loads(sarif_resp["data_json"])["path"].endswith(".sarif")


def test_callback_extract_allows_heuristic_mongodb_profile(monkeypatch):
    from stealthix import _tui_callback_extract as extract_mod

    callback = build_tui_callback()
    monkeypatch.setattr(extract_mod, "apply_plugin", lambda session: None)
    monkeypatch.setattr(extract_mod, "enumerate_databases", lambda session: {"databases": ["app"]})
    session_payload = {
        "config": {
            "base_url": "http://example.com",
            "method": "GET",
            "verify_tls": True,
            "dbms": "mongodb",
        },
        "metadata": {},
        "history": [],
        "creds": {},
    }

    resp = callback("extract.enum_databases", {"session": session_payload})
    assert resp["ok"] is True
    assert '"app"' in resp["data_json"]
