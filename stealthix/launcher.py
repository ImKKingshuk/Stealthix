from __future__ import annotations

from stealthix.headless import initialize_runtime
from stealthix.tui_callback import build_tui_callback
from stealthix.utils.rust import load_rust_core


def launch_tui(config_path: str | None = None, log_level: str = "INFO") -> int:
    _, config_data = initialize_runtime(config_path, log_level)
    rust_core = load_rust_core()
    run_tui = rust_core.get("run_tui")
    if not callable(run_tui):
        raise SystemExit(
            "Rust TUI is not available. Rebuild the stealthix.stealthix_core extension first."
        )
    run_tui(build_tui_callback(initial_config=config_data))
    return 0
