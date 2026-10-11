import importlib

from stealthix.utils import load_rust_core


def test_native_extension_import_path():
    native = importlib.import_module("stealthix.stealthix_core")
    assert native is not None


def test_load_rust_core():
    rust = load_rust_core()
    assert "HttpClient" in rust
    assert "AdaptivePoolState" in rust
    assert "PayloadEncoder" in rust
    assert "apply_tamper" in rust
    assert "list_tamper_scripts" in rust
    assert "run_tui" in rust


def test_utils_exports():
    from stealthix.core.session import ScanSession, SessionConfig
    from stealthix.utils import RequestCache, apply_waf_bypass, get_cache

    cache = RequestCache(max_items=10, ttl_seconds=60)
    cache.set(("http://example.com", "GET"), "cached_val")
    assert cache.get(("http://example.com", "GET")) == "cached_val"
    assert get_cache() is not None

    session = ScanSession(config=SessionConfig(url="http://example.com"))
    bypassed = apply_waf_bypass(session, "' UNION SELECT 1--")
    assert isinstance(bypassed, str)
    assert len(bypassed) > 0
