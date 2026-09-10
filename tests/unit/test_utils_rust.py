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
