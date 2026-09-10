from __future__ import annotations

from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin

from stealthix.core.session import ScanSession

_CSRF_HINTS = ("csrf", "xsrf", "authenticity", "token", "nonce", "_token")
_SKIP_TARGET_TYPES = {"submit", "button", "reset", "image"}


def _is_csrf_name(value: str) -> bool:
    lowered = value.strip().lower()
    return bool(lowered) and any(token in lowered for token in _CSRF_HINTS)


def _default_field_value(field_type: str, value: str, options: list[str]) -> str:
    normalized = field_type.lower()
    if value:
        return value
    if options:
        return options[0]
    if normalized in {"checkbox", "radio"}:
        return "on"
    if normalized == "email":
        return "test@example.com"
    if normalized in {"number", "range"}:
        return "1"
    if normalized == "file":
        return "stealthix.txt"
    return "test"


@dataclass(slots=True)
class FormField:
    name: str
    field_type: str = "text"
    value: str = ""
    required: bool = False
    hidden: bool = False
    csrf: bool = False
    file_upload: bool = False
    options: list[str] = field(default_factory=list)

    def resolved_value(self) -> str:
        return _default_field_value(self.field_type, self.value, self.options)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.field_type,
            "value": self.value,
            "required": self.required,
            "hidden": self.hidden,
            "csrf": self.csrf,
            "file_upload": self.file_upload,
            "options": list(self.options),
        }


@dataclass(slots=True)
class DiscoveredForm:
    source_url: str
    action: str
    method: str
    enctype: str
    fields: list[FormField] = field(default_factory=list)
    form_name: str | None = None
    form_id: str | None = None

    @property
    def multipart(self) -> bool:
        return "multipart/form-data" in self.enctype.lower()

    @property
    def file_fields(self) -> list[str]:
        return [field.name for field in self.fields if field.file_upload]

    @property
    def csrf_fields(self) -> list[str]:
        return [field.name for field in self.fields if field.csrf]

    @property
    def target_fields(self) -> list[str]:
        return [
            field.name
            for field in self.fields
            if field.name
            and field.field_type.lower() not in _SKIP_TARGET_TYPES
            and not field.hidden
            and not field.csrf
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_url": self.source_url,
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "multipart": self.multipart,
            "form_name": self.form_name,
            "form_id": self.form_id,
            "csrf_fields": self.csrf_fields,
            "file_fields": self.file_fields,
            "target_fields": self.target_fields,
            "fields": [field.to_dict() for field in self.fields],
        }


class _FormHTMLParser(HTMLParser):
    def __init__(self, page_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.page_url = page_url
        self.forms: list[DiscoveredForm] = []
        self._current: DiscoveredForm | None = None
        self._textarea: FormField | None = None
        self._select: FormField | None = None
        self._option_value: str | None = None
        self._option_selected = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {str(key).lower(): str(value or "") for key, value in attrs}
        normalized = tag.lower()
        if normalized == "form":
            action = urljoin(self.page_url, attrs_map.get("action") or self.page_url)
            method = (attrs_map.get("method") or "GET").upper()
            enctype = attrs_map.get("enctype") or "application/x-www-form-urlencoded"
            self._current = DiscoveredForm(
                source_url=self.page_url,
                action=action,
                method=method,
                enctype=enctype,
                form_name=attrs_map.get("name") or None,
                form_id=attrs_map.get("id") or None,
            )
            return
        if self._current is None:
            return
        if normalized == "input":
            field_type = (attrs_map.get("type") or "text").lower()
            name = attrs_map.get("name") or attrs_map.get("id")
            if not name:
                return
            field = FormField(
                name=name,
                field_type=field_type,
                value=attrs_map.get("value", ""),
                required=("required" in attrs_map),
                hidden=field_type == "hidden",
                csrf=_is_csrf_name(name) or _is_csrf_name(attrs_map.get("id", "")),
                file_upload=field_type == "file",
            )
            self._current.fields.append(field)
            return
        if normalized == "textarea":
            name = attrs_map.get("name") or attrs_map.get("id")
            if not name:
                return
            self._textarea = FormField(
                name=name,
                field_type="textarea",
                required=("required" in attrs_map),
                csrf=_is_csrf_name(name),
            )
            self._current.fields.append(self._textarea)
            return
        if normalized == "select":
            name = attrs_map.get("name") or attrs_map.get("id")
            if not name:
                return
            self._select = FormField(
                name=name,
                field_type="select",
                required=("required" in attrs_map),
                csrf=_is_csrf_name(name),
            )
            self._current.fields.append(self._select)
            return
        if normalized == "option" and self._select is not None:
            self._option_value = attrs_map.get("value", "")
            self._option_selected = "selected" in attrs_map

    def handle_data(self, data: str) -> None:
        if self._textarea is not None:
            self._textarea.value += data
        if self._select is not None and self._option_value is not None:
            option = self._option_value or data.strip()
            if option:
                self._select.options.append(option)
                if self._option_selected and not self._select.value:
                    self._select.value = option

    def handle_endtag(self, tag: str) -> None:
        normalized = tag.lower()
        if normalized == "textarea":
            self._textarea = None
            return
        if normalized == "option":
            self._option_value = None
            self._option_selected = False
            return
        if normalized == "select":
            self._select = None
            return
        if normalized == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def parse_forms(page_url: str, html: str) -> list[DiscoveredForm]:
    parser = _FormHTMLParser(page_url)
    parser.feed(html or "")
    return parser.forms


def build_form_targets(
    base_session: ScanSession,
    forms: list[DiscoveredForm],
    *,
    include_hidden_targets: bool = False,
    include_file_targets: bool = False,
) -> list[dict[str, Any]]:
    targets: list[dict[str, Any]] = []
    for form in forms:
        data: dict[str, Any] = {}
        target_params: list[str] = []
        multipart_fields: list[str] = []
        for form_field in form.fields:
            if not form_field.name:
                continue
            data[form_field.name] = form_field.resolved_value()
            field_type = form_field.field_type.lower()
            if form_field.file_upload:
                multipart_fields.append(form_field.name)
            injectable = field_type not in _SKIP_TARGET_TYPES and not form_field.csrf
            if form_field.hidden and not include_hidden_targets:
                injectable = False
            if form_field.file_upload and not include_file_targets:
                injectable = False
            if injectable:
                target_params.append(form_field.name)
        if not target_params:
            continue
        metadata = {
            "origin": "crawl-form",
            "source_url": form.source_url,
            "form": form.to_dict(),
            "csrf_fields": form.csrf_fields,
            "multipart_fields": multipart_fields,
            "form_multipart": form.multipart,
        }
        targets.append(
            {
                "url": form.action,
                "method": form.method,
                "data": data,
                "body_format": "form",
                "target_params": target_params,
                "metadata": metadata,
            }
        )
    return _dedupe_targets(base_session, targets)


def _dedupe_targets(
    _base_session: ScanSession, targets: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, tuple[tuple[str, str], ...], tuple[str, ...]]] = set()
    deduped: list[dict[str, Any]] = []
    for target in targets:
        data = target.get("data") if isinstance(target.get("data"), dict) else {}
        key = (
            str(target.get("method") or "GET").upper(),
            str(target.get("url") or ""),
            tuple(sorted((str(k), str(v)) for k, v in data.items()))
            if isinstance(data, dict)
            else (),
            tuple(sorted(str(item) for item in target.get("target_params") or [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(target)
    return deduped


__all__ = ["DiscoveredForm", "FormField", "build_form_targets", "parse_forms"]
