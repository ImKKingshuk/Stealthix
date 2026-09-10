from __future__ import annotations

from stealthix.core.engine import Engine
from stealthix.core.models import Finding, ScanResult
from stealthix.core.session import ScanSession, SessionConfig
from stealthix.crawler.form_parser import build_form_targets, parse_forms
from stealthix.crawler.spider import Spider, SpiderOptions, _sitemap_urls


def test_form_parser_builds_multipart_targets_and_preserves_csrf_fields():
    html = """
    <form method="post" action="/upload" enctype="multipart/form-data">
      <input type="hidden" name="csrf_token" value="abc123" />
      <input type="text" name="username" value="alice" />
      <input type="file" name="avatar" />
    </form>
    """
    session = ScanSession(SessionConfig(base_url="http://example.com/profile"))

    forms = parse_forms("http://example.com/profile", html)
    targets = build_form_targets(session, forms)

    assert len(forms) == 1
    assert forms[0].multipart is True
    assert forms[0].csrf_fields == ["csrf_token"]
    assert forms[0].file_fields == ["avatar"]
    assert targets == [
        {
            "url": "http://example.com/upload",
            "method": "POST",
            "data": {"csrf_token": "abc123", "username": "alice", "avatar": "stealthix.txt"},
            "body_format": "form",
            "target_params": ["username"],
            "metadata": {
                "origin": "crawl-form",
                "source_url": "http://example.com/profile",
                "form": forms[0].to_dict(),
                "csrf_fields": ["csrf_token"],
                "multipart_fields": ["avatar"],
                "form_multipart": True,
            },
        }
    ]


def test_spider_discovers_links_forms_robots_sitemap_and_static_js_urls(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com/"))
    responses = {
        "http://example.com/robots.txt": "User-agent: *\nDisallow: /admin\nSitemap: http://example.com/sitemap.xml\n",
        "http://example.com/sitemap.xml": "<urlset><url><loc>http://example.com/products?id=2</loc></url></urlset>",
        "http://example.com/": (
            "<a href='/search?q=test'>Search</a>"
            "<iframe src='/frame?view=1'></iframe>"
            "<form method='post' action='/login'><input name='username' value='alice'><input type='hidden' name='csrf' value='abc'></form>"
            "<script src='/static/app.js'></script>"
            "<script>const api = '/api/items?id=3';</script>"
        ),
        "http://example.com/static/app.js": "fetch('/report?year=2024')",
        "http://example.com/search?q=test": "<html></html>",
        "http://example.com/frame?view=1": "<html></html>",
        "http://example.com/products?id=2": "<html></html>",
        "http://example.com/api/items?id=3": "<html></html>",
        "http://example.com/report?year=2024": "<html></html>",
        "http://example.com/admin": "<html></html>",
    }

    def fake_make_request(_session, url, method="GET", use_cache=True):
        assert method == "GET"
        assert use_cache is True
        return str(responses[url]), 0.01

    monkeypatch.setattr("stealthix.crawler.spider.make_request", fake_make_request)

    result = Spider(session, options=SpiderOptions(max_depth=2, max_pages=10, scope="host")).crawl()
    target_urls = {(item["method"], item["url"]) for item in result["targets"]}

    assert "http://example.com/admin" in result["robots_urls"]
    assert "http://example.com/products?id=2" in result["sitemap_urls"]
    assert "http://example.com/static/app.js" in result["javascript_urls"]
    assert ("GET", "http://example.com/search?q=test") in target_urls
    assert ("GET", "http://example.com/frame?view=1") in target_urls
    assert ("GET", "http://example.com/api/items?id=3") in target_urls
    assert ("GET", "http://example.com/report?year=2024") in target_urls
    assert ("POST", "http://example.com/login") in target_urls


def test_sitemap_parser_rejects_external_entities():
    xml = """<?xml version="1.0"?>
    <!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
    <urlset><url><loc>&xxe;</loc></url></urlset>
    """

    assert _sitemap_urls(xml) == []


def test_engine_scan_site_aggregates_per_target_results(monkeypatch):
    session = ScanSession(SessionConfig(base_url="http://example.com"))
    crawl_result = {
        "base_url": "http://example.com",
        "targets": [
            {
                "url": "http://example.com/search?q=test",
                "method": "GET",
                "target_params": ["q"],
                "metadata": {"origin": "crawl-url"},
            },
            {
                "url": "http://example.com/login",
                "method": "POST",
                "data": {"username": "alice"},
                "target_params": ["username"],
                "metadata": {"origin": "crawl-form"},
            },
        ],
        "page_count": 2,
        "target_count": 2,
    }

    monkeypatch.setattr(
        "stealthix.crawler.spider.Spider.crawl", lambda self, start_url=None: crawl_result
    )

    def fake_run_target_scan(self, spec, *, index, total):
        return ScanResult(
            target=spec["url"],
            findings=[
                Finding(kind="sqli", target=spec["url"], details={"index": index, "total": total})
            ],
            metadata={"scan_target": spec},
        )

    monkeypatch.setattr(Engine, "_run_target_scan", fake_run_target_scan)

    result = Engine(session).scan_site()

    assert len(result.findings) == 2
    assert result.metadata["site_scan"] is True
    assert result.metadata["crawl"]["target_count"] == 2
    assert len(result.metadata["per_target_results"]) == 2
