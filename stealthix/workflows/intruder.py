from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from stealthix.workflows.requests import RequestSpec

_MARKER_RE = re.compile(r"§([A-Za-z0-9_.:-]+)§|\{\{([A-Za-z0-9_.:-]+)\}\}")


@dataclass(frozen=True)
class PayloadMarker:
    name: str
    location: str
    path: str


def find_payload_markers(spec: RequestSpec) -> list[PayloadMarker]:
    markers: list[PayloadMarker] = []
    _collect_string_markers(spec.url, markers, location="url", path="url")
    for key, value in spec.headers.items():
        _collect_string_markers(str(value), markers, location="header", path=str(key))
    for key, value in spec.cookies.items():
        _collect_string_markers(str(value), markers, location="cookie", path=str(key))
    _collect_data_markers(spec.data, markers, location="body", path="data")
    if spec.raw_body:
        _collect_string_markers(spec.raw_body, markers, location="raw_body", path="raw_body")
    return _dedupe_markers(markers)


def expand_payload_positions(
    spec: RequestSpec,
    payloads: Mapping[str, Sequence[str]] | Sequence[str],
    *,
    mode: str = "clusterbomb",
    limit: int | None = None,
) -> list[RequestSpec]:
    marker_names = list(dict.fromkeys(marker.name for marker in find_payload_markers(spec)))
    if not marker_names:
        return [spec]
    payload_map = _payload_map(marker_names, payloads)
    assignments = _assignments(marker_names, payload_map, mode=mode)
    expanded: list[RequestSpec] = []
    for assignment in assignments:
        expanded.append(_replace_spec_markers(spec, assignment))
        if limit is not None and len(expanded) >= limit:
            break
    return expanded


def _collect_string_markers(
    value: str, markers: list[PayloadMarker], *, location: str, path: str
) -> None:
    for match in _MARKER_RE.finditer(value):
        markers.append(
            PayloadMarker(name=match.group(1) or match.group(2), location=location, path=path)
        )


def _collect_data_markers(
    value: Any, markers: list[PayloadMarker], *, location: str, path: str
) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _collect_data_markers(child, markers, location=location, path=f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _collect_data_markers(child, markers, location=location, path=f"{path}[{index}]")
    elif isinstance(value, str):
        _collect_string_markers(value, markers, location=location, path=path)


def _dedupe_markers(markers: list[PayloadMarker]) -> list[PayloadMarker]:
    seen: set[tuple[str, str, str]] = set()
    output: list[PayloadMarker] = []
    for marker in markers:
        key = (marker.name, marker.location, marker.path)
        if key in seen:
            continue
        seen.add(key)
        output.append(marker)
    return output


def _payload_map(
    marker_names: list[str], payloads: Mapping[str, Sequence[str]] | Sequence[str]
) -> dict[str, list[str]]:
    if isinstance(payloads, Mapping):
        payload_mapping = cast(Mapping[str, Sequence[str]], payloads)
        result: dict[str, list[str]] = {}
        for name in marker_names:
            values = payload_mapping.get(name)
            if values:
                result[name] = [str(item) for item in values]
        return result
    shared = [str(item) for item in payloads]
    return dict.fromkeys(marker_names, shared)


def _assignments(
    marker_names: list[str], payload_map: dict[str, list[str]], *, mode: str
) -> Iterable[dict[str, str]]:
    normalized_mode = str(mode or "clusterbomb").lower()
    names = [name for name in marker_names if payload_map.get(name)]
    if normalized_mode == "pitchfork":
        for values in zip(*(payload_map[name] for name in names), strict=False):
            yield dict(zip(names, values, strict=False))
        return
    if normalized_mode == "sniper":
        for name in names:
            for payload in payload_map[name]:
                yield dict.fromkeys(names, "") | {name: payload}
        return
    if normalized_mode != "clusterbomb":
        raise ValueError("mode must be one of: clusterbomb, pitchfork, sniper")
    for values in itertools.product(*(payload_map[name] for name in names)):
        yield dict(zip(names, values, strict=False))


def _replace_spec_markers(spec: RequestSpec, values: dict[str, str]) -> RequestSpec:
    return spec.with_updates(
        url=_replace_markers(spec.url, values),
        headers={key: _replace_markers(value, values) for key, value in spec.headers.items()},
        cookies={key: _replace_markers(value, values) for key, value in spec.cookies.items()},
        data=_replace_data(spec.data, values),
        raw_body=_replace_markers(spec.raw_body, values) if spec.raw_body is not None else None,
        metadata={**spec.metadata, "intruder_payloads": dict(values)},
    )


def _replace_data(value: Any, values: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_data(child, values) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_data(child, values) for child in value]
    if isinstance(value, str):
        return _replace_markers(value, values)
    return value


def _replace_markers(value: str | None, values: dict[str, str]) -> str:
    if value is None:
        return ""

    def repl(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        return values.get(name, match.group(0))

    return _MARKER_RE.sub(repl, value)


__all__ = ["PayloadMarker", "expand_payload_positions", "find_payload_markers"]
