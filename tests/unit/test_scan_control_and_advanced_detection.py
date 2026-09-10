import json
import threading
import time

from stealthix.core.control import ScanControl
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.core.targeting import InjectionPoint, record_tested_param
from stealthix.detection.graphql import detect_graphql
from stealthix.plugins.runtime import run_plugin_checks


def test_scan_control_pause_and_active_elapsed():
    ctrl = ScanControl()
    started = time.monotonic()
    time.sleep(0.02)
    ctrl.set_paused(True)
    time.sleep(0.05)
    ctrl.set_paused(False)
    elapsed = ctrl.active_elapsed(started)
    assert elapsed < 0.08


def test_record_tested_param_dedupes():
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    p = InjectionPoint(name="id", location="query")
    record_tested_param(session, module="sqli", point=p)
    record_tested_param(session, module="sqli", point=p)
    tested = session.metadata.get("tested_params")
    assert isinstance(tested, list)
    assert len(tested) == 1


def test_plugin_checks_update_fingerprint(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com", level=3))
    plugin_dict = {
        "name": "mysql",
        "version_queries": ["' UNION SELECT @@version--"],
        "privilege_checks": ["' UNION SELECT user()--"],
        "os_queries": ["' UNION SELECT @@version_compile_os--"],
    }

    def fake_request(_session, _url, _data=None, _method=None):
        return ("MySQL 8.0.33 linux root@localhost", 0.01)

    monkeypatch.setattr("stealthix.detection.common._make_request", fake_request)
    run_plugin_checks(session, plugin_dict)
    fp = session.metadata.get("fingerprint")
    assert isinstance(fp, dict)
    assert any(k in fp for k in ["os", "dbms_version", "current_user", "is_admin"])


def test_graphql_detection_probes(monkeypatch):
    session = ScanSession(
        SessionConfig(
            base_url="http://example.com/graphql",
            method="POST",
            body_format="json",
            data={"query": "{__typename}"},
        )
    )

    class Dummy:
        def __init__(self, text):
            self.text = text
            self.status_code = 200
            self.headers = {}

    def fake_post(
        url, headers=None, cookies=None, json=None, proxies=None, timeout=None, verify=None
    ):
        query = (json or {}).get("query", "")
        if query == "{__typename}":
            return Dummy(json_module.dumps({"data": {"__typename": "Query"}}))
        if "__schema" in query:
            return Dummy(json_module.dumps({"data": {"__schema": {"types": [{"name": "Query"}]}}}))
        if "__nonexistentField" in query:
            return Dummy(json_module.dumps({"errors": [{"message": "Cannot query field"}]}))
        return Dummy(json_module.dumps({"data": {"__typename": "Query"}}))

    json_module = json
    monkeypatch.setattr("stealthix.detection.graphql.requests.post", fake_post)
    findings = detect_graphql(session)
    kinds = {f.kind for f in findings}
    assert "graphql-endpoint" in kinds
    assert "graphql-error-probe" in kinds
