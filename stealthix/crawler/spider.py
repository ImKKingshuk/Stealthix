from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse
from xml.etree.ElementTree import ParseError

from defusedxml import ElementTree as DefusedET
from defusedxml.common import DefusedXmlException

from stealthix.core.http import make_request
from stealthix.core.session import ScanSession
from stealthix.crawler.form_parser import build_form_targets, parse_forms

_JS_URL_RE = re.compile(r"['\"]((?:https?://|/|\.\.?/)[^'\"\s<>#]+)['\"]")
_ROBOTS_PATH_RE = re.compile(r"^(?:allow|disallow):\s*(.+)$", re.IGNORECASE)
_ROBOTS_SITEMAP_RE = re.compile(r"^sitemap:\s*(.+)$", re.IGNORECASE)


@dataclass(slots=True)
class SpiderOptions:
    max_depth: int = 2
    max_pages: int = 50
    scope: str = "host"
    parse_robots: bool = True
    parse_sitemap: bool = True
    fetch_scripts: bool = True


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.urls: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._script_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_map = {str(key).lower(): str(value or "") for key, value in attrs}
        normalized = tag.lower()
        attr_name = {
            "a": "href",
            "link": "href",
            "area": "href",
            "iframe": "src",
            "frame": "src",
            "script": "src",
            "img": "src",
            "audio": "src",
            "video": "src",
            "source": "src",
            "embed": "src",
            "form": "action",
        }.get(normalized)
        if attr_name and attrs_map.get(attr_name):
            self.urls.append(attrs_map[attr_name])
        if normalized == "script":
            self._in_script = True
            self._script_parts = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            script = "".join(self._script_parts).strip()
            if script:
                self.inline_scripts.append(script)
            self._in_script = False
            self._script_parts = []


def _normalize_url(base_url: str, candidate: str) -> str | None:
    joined = urljoin(base_url, candidate.strip())
    parsed = urlparse(joined)
    if parsed.scheme not in {"http", "https"}:
        return None
    query = "&".join(
        f"{key}={value}" if value else key
        for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True))
    )
    netloc = parsed.netloc.lower()
    if parsed.port == 80 and parsed.scheme == "http":
        netloc = parsed.hostname or netloc
    if parsed.port == 443 and parsed.scheme == "https":
        netloc = parsed.hostname or netloc
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, netloc, path, "", query, ""))


def _registrable_domain(host: str) -> str:
    parts = [part for part in host.lower().split(".") if part]
    return ".".join(parts[-2:]) if len(parts) >= 2 else host.lower()


def _in_scope(base_url: str, candidate: str, scope: str) -> bool:
    base_host = (urlparse(base_url).hostname or "").lower()
    candidate_host = (urlparse(candidate).hostname or "").lower()
    if scope == "any" or not base_host or not candidate_host:
        return True
    if scope == "host":
        return base_host == candidate_host
    return candidate_host == base_host or candidate_host.endswith(
        "." + _registrable_domain(base_host)
    )


def _query_target(url: str, *, source: str, depth: int) -> dict[str, Any] | None:
    params = [key for key, _value in parse_qsl(urlparse(url).query, keep_blank_values=True)]
    if not params:
        return None
    return {
        "url": url,
        "method": "GET",
        "data": None,
        "body_format": "form",
        "target_params": list(dict.fromkeys(params)),
        "metadata": {"origin": source, "depth": depth},
    }


def _extract_js_urls(base_url: str, content: str) -> list[str]:
    urls: list[str] = []
    for match in _JS_URL_RE.finditer(content or ""):
        if normalized := _normalize_url(base_url, match.group(1)):
            urls.append(normalized)
    return list(dict.fromkeys(urls))


def _robots_targets(base_url: str, body: str) -> tuple[list[str], list[str]]:
    urls: list[str] = []
    sitemaps: list[str] = []
    for line in (body or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if match := _ROBOTS_SITEMAP_RE.match(stripped):
            if normalized := _normalize_url(base_url, match.group(1)):
                sitemaps.append(normalized)
            continue
        if match := _ROBOTS_PATH_RE.match(stripped):
            value = match.group(1).strip()
            if value and value != "/" and (normalized := _normalize_url(base_url, value)):
                urls.append(normalized)
    return list(dict.fromkeys(urls)), list(dict.fromkeys(sitemaps))


def _sitemap_urls(xml_text: str) -> list[str]:
    urls: list[str] = []
    if not xml_text.strip():
        return urls
    try:
        root = DefusedET.fromstring(xml_text)
    except (ParseError, DefusedXmlException):
        return urls
    for elem in root.iter():
        if elem.tag.endswith("loc") and elem.text and elem.text.strip():
            urls.append(elem.text.strip())
    return list(dict.fromkeys(urls))


class Spider:
    def __init__(self, session: ScanSession, *, options: SpiderOptions | None = None) -> None:
        self.session = session.clone_for_worker()
        self.session.config.method = "GET"
        self.session.config.data = None
        self.options = options or SpiderOptions()

    def _fetch(self, url: str) -> tuple[str, float]:
        return make_request(self.session, url, method="GET", use_cache=True)

    def crawl(self, start_url: str | None = None) -> dict[str, Any]:
        base_url = start_url or self.session.config.base_url
        normalized_start = _normalize_url(base_url, base_url) or base_url
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque([(normalized_start, 0)])
        pages: list[dict[str, Any]] = []
        forms: list[dict[str, Any]] = []
        targets: list[dict[str, Any]] = []
        robots_urls: list[str] = []
        sitemap_urls: list[str] = []
        script_urls: list[str] = []

        def enqueue(url: str, depth: int) -> None:
            if depth > self.options.max_depth or url in visited:
                return
            if not _in_scope(normalized_start, url, self.options.scope):
                return
            queue.append((url, depth))

        if self.options.parse_robots:
            robots_url = _normalize_url(normalized_start, "/robots.txt")
            if robots_url:
                try:
                    robots_body, _ = self._fetch(robots_url)
                    seeded, sitemaps = _robots_targets(normalized_start, robots_body)
                    robots_urls.extend(seeded)
                    sitemap_urls.extend(sitemaps)
                    for url in seeded:
                        enqueue(url, 1)
                except Exception:
                    pass

        if self.options.parse_sitemap:
            candidate_sitemaps = list(
                dict.fromkeys(
                    [*(sitemap_urls or []), _normalize_url(normalized_start, "/sitemap.xml") or ""]
                )
            )
            for sitemap in [item for item in candidate_sitemaps if item]:
                try:
                    xml_text, _ = self._fetch(sitemap)
                    for url in _sitemap_urls(xml_text):
                        if normalized := _normalize_url(normalized_start, url):
                            sitemap_urls.append(normalized)
                            enqueue(normalized, 1)
                except Exception:
                    continue

        while queue and len(visited) < self.options.max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited:
                continue
            visited.add(current_url)
            try:
                body, elapsed = self._fetch(current_url)
            except Exception as exc:
                pages.append(
                    {
                        "url": current_url,
                        "depth": depth,
                        "error": str(exc),
                        "links": [],
                        "forms": [],
                    }
                )
                continue
            doc_parser = _DocumentParser()
            doc_parser.feed(body)
            normalized_links = [
                normalized
                for raw in doc_parser.urls
                if (normalized := _normalize_url(current_url, raw))
                and _in_scope(normalized_start, normalized, self.options.scope)
            ]
            inline_js_urls = [
                normalized
                for script in doc_parser.inline_scripts
                for normalized in _extract_js_urls(current_url, script)
                if _in_scope(normalized_start, normalized, self.options.scope)
            ]
            form_objects = parse_forms(current_url, body)
            form_dicts = [form.to_dict() for form in form_objects]
            forms.extend(form_dicts)
            targets.extend(item for item in build_form_targets(self.session, form_objects))
            page_target = _query_target(current_url, source="crawl-url", depth=depth)
            if page_target is not None:
                targets.append(page_target)
            for discovered_url in [*normalized_links, *inline_js_urls]:
                if discovered_url.endswith(".js"):
                    script_urls.append(discovered_url)
                    if self.options.fetch_scripts:
                        try:
                            js_body, _ = self._fetch(discovered_url)
                            for extra in _extract_js_urls(discovered_url, js_body):
                                enqueue(extra, depth + 1)
                        except Exception:
                            pass
                enqueue(discovered_url, depth + 1)
            pages.append(
                {
                    "url": current_url,
                    "depth": depth,
                    "elapsed": elapsed,
                    "links": list(dict.fromkeys(normalized_links + inline_js_urls)),
                    "forms": form_dicts,
                }
            )

        deduped_targets: list[dict[str, Any]] = []
        seen_targets: set[tuple[str, str, tuple[tuple[str, str], ...], tuple[str, ...]]] = set()
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
            if key in seen_targets:
                continue
            seen_targets.add(key)
            deduped_targets.append(target)

        return {
            "base_url": normalized_start,
            "visited_urls": sorted(visited),
            "pages": pages,
            "forms": forms,
            "targets": deduped_targets,
            "robots_urls": sorted(dict.fromkeys(robots_urls)),
            "sitemap_urls": sorted(dict.fromkeys(sitemap_urls)),
            "javascript_urls": sorted(dict.fromkeys(script_urls)),
            "scope": self.options.scope,
            "max_depth": self.options.max_depth,
            "max_pages": self.options.max_pages,
            "page_count": len(pages),
            "target_count": len(deduped_targets),
        }


__all__ = ["Spider", "SpiderOptions"]
