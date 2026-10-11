"""
Technology detection module for reconnaissance.
"""

import json
import re
from pathlib import Path
from typing import Any

from stealthix.core.errors import ReconError
from stealthix.core.http import make_request
from stealthix.core.session import ScanSession
from stealthix.recon.models import Fingerprint, TechnologyMatch


class TechDetector:
    """Detects web technologies through fingerprinting."""

    def __init__(self, session: ScanSession):
        self.session = session
        self.fingerprints = self._load_fingerprints()
        self._fingerprint_cache: dict[str, Any] = {}

    def _load_fingerprints(self) -> list[Fingerprint]:
        """Load built-in fingerprint signatures."""
        fingerprints_path = Path(__file__).parent / "fingerprints.json"
        try:
            with open(fingerprints_path, encoding="utf-8") as f:
                data = json.load(f)
                return [
                    Fingerprint(
                        name=fp["name"],
                        category=fp["category"],
                        patterns=fp["patterns"],
                        version_patterns=fp.get("version_patterns"),
                    )
                    for fp in data.get("fingerprints", [])
                ]
        except ReconError as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Failed to load fingerprints: {exc}"
            )
            return []

    def detect(self) -> list[TechnologyMatch]:
        """
        Detect all technologies on target.

        Returns list of TechnologyMatch objects with confidence scores.
        """
        matches: list[TechnologyMatch] = []

        try:
            # Make initial request to get headers and body
            response = make_request(
                self.session,
                method="GET",
                url=self.session.config.base_url,
                data=None,
            )

            if not response:
                return matches

            body = response[0] if isinstance(response, tuple) else str(response)

            # Retrieve headers and metadata from session history if available
            history_entry = next(
                (
                    entry
                    for entry in reversed(self.session.history.to_list())
                    if entry.get("url") == self.session.config.base_url
                ),
                {},
            )
            metadata = (
                history_entry.get("metadata")
                if isinstance(history_entry.get("metadata"), dict)
                else {}
            )
            headers = dict(metadata.get("headers") or {}) if isinstance(metadata, dict) else {}
            cookies = dict(self.session.config.cookies or {})

            # If headers were not captured in metadata (e.g. transport omission), attempt direct inspection
            if not headers:
                try:
                    import requests as requests_lib

                    proxy = self.session.config.proxy
                    proxies = {"http": proxy, "https": proxy} if proxy else None
                    full_response = requests_lib.get(
                        self.session.config.base_url,
                        headers=dict(self.session.config.headers or {}),
                        cookies=dict(self.session.config.cookies or {}),
                        timeout=self.session.config.timeout,
                        proxies=proxies,
                        verify=self.session.config.verify_tls,
                    )
                    headers = dict(full_response.headers)
                    body = full_response.text
                    cookies.update(dict(full_response.cookies))
                except Exception:
                    pass

            # Match each fingerprint
            for fingerprint in self.fingerprints:
                matched, confidence, evidence = self._match_fingerprint(
                    fingerprint, headers, body, cookies
                )

                if matched:
                    version = self._extract_version(fingerprint, headers, body)
                    matches.append(
                        TechnologyMatch(
                            category=fingerprint.category,
                            name=fingerprint.name,
                            version=version,
                            confidence=confidence,
                            evidence=evidence,
                        )
                    )

        except ReconError as exc:
            self.session.metadata.setdefault("recon_errors", []).append(
                f"Technology detection failed: {exc}"
            )

        # Deduplicate and return
        return self._deduplicate_matches(matches)

    def _match_fingerprint(
        self,
        fingerprint: Fingerprint,
        headers: dict[str, str],
        body: str,
        cookies: Any,
    ) -> tuple[bool, float, list[dict[str, Any]]]:
        """Match fingerprint against response data."""
        evidence: list[dict[str, Any]] = []
        total_weight = 0.0
        matched_weight = 0.0

        for pattern in fingerprint.patterns:
            total_weight += pattern.get("weight", 0.5)

            if pattern["type"] == "header":
                matched, ev = self._match_headers(headers, pattern)
                if matched:
                    matched_weight += pattern.get("weight", 0.5)
                    evidence.append(ev)

            elif pattern["type"] == "body":
                matched, ev = self._match_body(body, pattern)
                if matched:
                    matched_weight += pattern.get("weight", 0.5)
                    evidence.append(ev)

            elif pattern["type"] == "cookie":
                matched, ev = self._match_cookies(cookies, pattern)
                if matched:
                    matched_weight += pattern.get("weight", 0.5)
                    evidence.append(ev)

        # Calculate confidence
        if total_weight > 0:
            confidence = matched_weight / total_weight
        else:
            confidence = 0.0

        # Consider it a match if confidence >= 0.5
        is_match = confidence >= 0.5

        return is_match, confidence, evidence

    def _match_headers(
        self, headers: dict[str, str], pattern: dict[str, Any]
    ) -> tuple[bool, dict[str, Any]]:
        """Match fingerprint against HTTP headers."""
        key = pattern.get("key", "")
        pattern_str = pattern.get("pattern", "")
        is_regex = pattern.get("regex", False)

        # Case-insensitive header lookup
        header_value = None
        for h_key, h_val in headers.items():
            if h_key.lower() == key.lower():
                header_value = h_val
                break

        if not header_value:
            return False, {}

        # Match pattern
        if is_regex:
            cache_key = f"regex:{pattern_str}"
            if cache_key not in self._fingerprint_cache:
                self._fingerprint_cache[cache_key] = re.compile(pattern_str, re.IGNORECASE)
            regex = self._fingerprint_cache[cache_key]
            match = regex.search(header_value)
            matched = match is not None
        else:
            matched = pattern_str.lower() in header_value.lower()

        if matched:
            return True, {
                "type": "header",
                "key": key,
                "value": header_value,
                "weight": pattern.get("weight", 0.5),
            }

        return False, {}

    def _match_body(self, body: str, pattern: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Match fingerprint against response body."""
        pattern_str = pattern.get("pattern", "")
        is_regex = pattern.get("regex", False)

        if not body:
            return False, {}

        # Match pattern
        if is_regex:
            cache_key = f"regex:{pattern_str}"
            if cache_key not in self._fingerprint_cache:
                self._fingerprint_cache[cache_key] = re.compile(pattern_str, re.IGNORECASE)
            regex = self._fingerprint_cache[cache_key]
            match = regex.search(body)
            matched = match is not None
            match_text = match.group(0) if match else ""
        else:
            matched = pattern_str.lower() in body.lower()
            match_text = pattern_str if matched else ""

        if matched:
            return True, {
                "type": "body",
                "pattern": pattern_str,
                "match": match_text[:100],  # Truncate for evidence
                "weight": pattern.get("weight", 0.5),
            }

        return False, {}

    def _match_cookies(self, cookies: Any, pattern: dict[str, Any]) -> tuple[bool, dict[str, Any]]:
        """Match fingerprint against cookies."""
        key = pattern.get("key", "")
        pattern_str = pattern.get("pattern", "")
        is_regex = pattern.get("regex", False)

        if not cookies:
            return False, {}

        # Get cookie value
        cookie_value = cookies.get(key)
        if not cookie_value:
            return False, {}

        # Match pattern
        if is_regex:
            cache_key = f"regex:{pattern_str}"
            if cache_key not in self._fingerprint_cache:
                self._fingerprint_cache[cache_key] = re.compile(pattern_str)
            regex = self._fingerprint_cache[cache_key]
            match = regex.search(str(cookie_value))
            matched = match is not None
        else:
            matched = pattern_str in str(cookie_value)

        if matched:
            return True, {
                "type": "cookie",
                "key": key,
                "value": str(cookie_value)[:50],  # Truncate
                "weight": pattern.get("weight", 0.5),
            }

        return False, {}

    def _extract_version(
        self, fingerprint: Fingerprint, headers: dict[str, str], body: str
    ) -> str | None:
        """Extract version number from text using version patterns."""
        if not fingerprint.version_patterns:
            return None

        for vp in fingerprint.version_patterns:
            pattern_str = vp.get("pattern", "")
            if not pattern_str:
                continue

            cache_key = f"regex:{pattern_str}"
            if cache_key not in self._fingerprint_cache:
                self._fingerprint_cache[cache_key] = re.compile(pattern_str, re.IGNORECASE)
            regex = self._fingerprint_cache[cache_key]

            # Try header first
            if vp.get("type") == "header":
                key = vp.get("key", "")
                header_value = None
                for h_key, h_val in headers.items():
                    if h_key.lower() == key.lower():
                        header_value = h_val
                        break
                if header_value:
                    match = regex.search(header_value)
                    if match and match.groups():
                        return match.group(1)

            # Try body
            elif vp.get("type") == "body":
                match = regex.search(body)
                if match and match.groups():
                    return match.group(1)

        return None

    def _deduplicate_matches(self, matches: list[TechnologyMatch]) -> list[TechnologyMatch]:
        """Remove duplicate/conflicting matches, keeping highest confidence."""
        # Group by category
        by_category: dict[str, list[TechnologyMatch]] = {}
        for match in matches:
            if match.category not in by_category:
                by_category[match.category] = []
            by_category[match.category].append(match)

        # For each category, keep only the highest confidence match
        deduplicated: list[TechnologyMatch] = []
        for _category, category_matches in by_category.items():
            # Sort by confidence descending
            category_matches.sort(key=lambda m: m.confidence, reverse=True)
            # Keep the top match
            if category_matches:
                deduplicated.append(category_matches[0])

        return deduplicated
