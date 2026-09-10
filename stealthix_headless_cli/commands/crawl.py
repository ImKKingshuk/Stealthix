from __future__ import annotations

from pathlib import Path
from typing import Any

from stealthix.crawler import SpiderOptions


def crawl_options_from_args(args: Any, *, prefix: str = "crawl_") -> SpiderOptions:
    depth = getattr(args, f"{prefix}depth", None)
    max_pages = getattr(args, f"{prefix}max_pages", None)
    scope = getattr(args, f"{prefix}scope", None)
    parse_robots = getattr(args, f"{prefix}parse_robots", True)
    parse_sitemap = getattr(args, f"{prefix}parse_sitemap", True)
    return SpiderOptions(
        max_depth=max(0, int(depth if depth is not None else getattr(args, "depth", 2))),
        max_pages=max(
            1, int(max_pages if max_pages is not None else getattr(args, "max_pages", 50))
        ),
        scope=str(scope or getattr(args, "scope", "host")).lower(),
        parse_robots=bool(parse_robots),
        parse_sitemap=bool(parse_sitemap),
    )


def load_url_file(path: str | None) -> list[str]:
    if not path:
        return []
    return [
        line.strip() for line in Path(path).read_text(encoding="utf-8").splitlines() if line.strip()
    ]


__all__ = ["crawl_options_from_args", "load_url_file"]
