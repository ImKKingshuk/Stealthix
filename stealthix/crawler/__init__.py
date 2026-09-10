from __future__ import annotations

from typing import Any

__all__ = [
    "DiscoveredForm",
    "FormField",
    "Spider",
    "SpiderOptions",
    "build_form_targets",
    "parse_forms",
]


def __getattr__(name: str) -> Any:
    if name in {"DiscoveredForm", "FormField", "build_form_targets", "parse_forms"}:
        from stealthix.crawler.form_parser import (
            DiscoveredForm,
            FormField,
            build_form_targets,
            parse_forms,
        )

        return {
            "DiscoveredForm": DiscoveredForm,
            "FormField": FormField,
            "build_form_targets": build_form_targets,
            "parse_forms": parse_forms,
        }[name]
    if name in {"Spider", "SpiderOptions"}:
        from stealthix.crawler.spider import Spider, SpiderOptions

        return {"Spider": Spider, "SpiderOptions": SpiderOptions}[name]
    raise AttributeError(name)
