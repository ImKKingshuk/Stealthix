from __future__ import annotations

import json

from stealthix.proxy import (
    CapturedResponse,
    InterceptionQueue,
    InterceptionRule,
    ProxyWorkspace,
)
from stealthix.workflows.requests import import_raw_http


def test_proxy_workspace_persists_searches_and_exports(tmp_path) -> None:
    workspace = ProxyWorkspace(tmp_path / "proxy")
    request = import_raw_http(
        "POST /search?q=alice HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "Content-Type: application/json\r\n\r\n"
        '{"id": 42}'
    )

    record = workspace.capture_exchange(
        request,
        response=CapturedResponse(status_code=200, headers={"Server": "demo"}, body="ok"),
        tags=["sql"],
    )

    reloaded = ProxyWorkspace(tmp_path / "proxy")
    matches = reloaded.search("alice", method="POST", status=200, tag="sql", host="example.com")

    assert [item.id for item in matches] == [record.id]
    exported = json.loads(reloaded.export_payload())
    assert exported["records"][0]["request"]["url"] == "http://example.com/search?q=alice"
    assert reloaded.stats()["record_count"] == 1


def test_interception_queue_edits_and_persists_request(tmp_path) -> None:
    workspace = ProxyWorkspace(tmp_path / "proxy")
    request = import_raw_http("GET /admin?id=1 HTTP/1.1\r\nHost: example.com\r\n\r\n")
    record = workspace.capture_request(request, tags=["review"])
    queue = InterceptionQueue(
        rules=[InterceptionRule(id="admin", methods=("GET",), url_contains="/admin")],
        workspace=workspace,
    )

    intercepted = queue.offer(record)
    assert intercepted is not None
    edited = request.with_updates(url="http://example.com/admin?id=2")
    resolved = queue.resolve(
        intercepted.id, action="edit", edited_request=edited, note="mutated id"
    )

    assert resolved.state == "edited"
    assert workspace.get(record.id).request.url.endswith("id=2")
    assert workspace.get(record.id).metadata["interception"]["action"] == "edit"
