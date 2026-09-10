import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--live", action="store_true", default=False, help="Run live integration tests"
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "live: marks tests as live integration tests")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    import os

    if config.getoption("--live") or os.environ.get("STEALTHIX_LIVE") == "1":
        return
    skip_live = pytest.mark.skip(reason="live integration tests require STEALTHIX_LIVE=1 or --live")
    for item in items:
        if item.get_closest_marker("live"):
            item.add_marker(skip_live)
