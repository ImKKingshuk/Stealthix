"""Heuristic/statistical ML bypass for WAF detection and evasion.

This module provides ML-like detection and bypass capabilities without
external ML dependencies, using statistical analysis and heuristics.
"""

from __future__ import annotations

import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from stealthix.core.session import ScanSession


@dataclass
class WAFResponseFeatures:
    """Features extracted from WAF response for analysis."""

    status_code: int
    response_time_ms: float
    content_length: int
    headers: dict[str, str]
    body_snippet: str
    blocked_indicators: list[str] = field(default_factory=list)
    ml_indicators: list[str] = field(default_factory=list)


class MLWAFDetector:
    """Detect ML-based WAFs using statistical response pattern analysis.

    Uses heuristic methods to identify ML-based WAFs by analyzing
    response patterns, timing variations, and blocking signatures.
    """

    def __init__(self) -> None:
        self._baseline_responses: list[WAFResponseFeatures] = []
        self._ml_signature_patterns = [
            r"machine\s*learning",
            r"ai\s*powered",
            r"neural\s*network",
            r"deep\s*learning",
            r"model\s*inference",
            r"anomaly\s*detection",
            r"behavioral\s*analysis",
            r"adaptive\s*protection",
        ]
        self._ml_header_patterns = [
            r"x-ml-",
            r"x-ai-",
            r"x-neural-",
            r"x-model-",
            r"x-anomaly-",
        ]

    def extract_features(self, response: dict[str, Any]) -> WAFResponseFeatures:
        """Extract features from WAF response for analysis."""
        status_code = response.get("status_code", 0)
        response_time = response.get("response_time", 0.0)
        content_length = response.get("content_length", 0)
        headers = response.get("headers", {})
        body = response.get("text", "")[:500]  # First 500 chars

        blocked_indicators = self._extract_blocked_indicators(status_code, body, headers)
        ml_indicators = self._extract_ml_indicators(body, headers)

        return WAFResponseFeatures(
            status_code=status_code,
            response_time_ms=response_time,
            content_length=content_length,
            headers=headers,
            body_snippet=body,
            blocked_indicators=blocked_indicators,
            ml_indicators=ml_indicators,
        )

    def _extract_blocked_indicators(
        self, status_code: int, body: str, headers: dict[str, str]
    ) -> list[str]:
        """Extract indicators that suggest request was blocked."""
        indicators = []

        # Status code analysis
        if status_code in {403, 406, 429, 503}:
            indicators.append(f"status_{status_code}")

        # Common WAF block patterns in body
        block_patterns = [
            r"access\s*denied",
            r"blocked",
            r"forbidden",
            r"waf",
            r"firewall",
            r"security",
            r"protection",
            r"suspicious",
            r"malicious",
            r"attack",
        ]
        body_lower = body.lower()
        for pattern in block_patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                indicators.append(f"body_{pattern}")

        # WAF-specific headers
        waf_headers = ["x-waf", "x-firewall", "x-protection", "x-security"]
        for header in waf_headers:
            if any(h.lower().startswith(header) for h in headers):
                indicators.append(f"header_{header}")

        return indicators

    def _extract_ml_indicators(self, body: str, headers: dict[str, str]) -> list[str]:
        """Extract indicators that suggest ML-based WAF."""
        indicators = []

        # Body patterns
        body_lower = body.lower()
        for pattern in self._ml_signature_patterns:
            if re.search(pattern, body_lower, re.IGNORECASE):
                indicators.append(f"body_{pattern}")

        # Header patterns
        for header_name, header_value in headers.items():
            header_lower = header_name.lower()
            for pattern in self._ml_header_patterns:
                if re.search(pattern, header_lower, re.IGNORECASE):
                    indicators.append(f"header_{pattern}")
                if re.search(pattern, header_value.lower(), re.IGNORECASE):
                    indicators.append(f"header_value_{pattern}")

        return indicators

    def is_ml_waf(self, features: WAFResponseFeatures) -> tuple[bool, float]:
        """Determine if WAF is ML-based using statistical analysis."""
        confidence = 0.0

        # ML indicators in response
        if features.ml_indicators:
            confidence += 0.4 * len(features.ml_indicators)

        # Check for adaptive behavior (timing variance)
        if len(self._baseline_responses) >= 3:
            baseline_times = [r.response_time_ms for r in self._baseline_responses]

            # High variance suggests adaptive/ML-based analysis
            if baseline_times:
                time_stddev = statistics.stdev(baseline_times) if len(baseline_times) > 1 else 0
                if time_stddev > 50:  # 50ms variance threshold
                    confidence += 0.3

        # Check for consistent blocking patterns (rule-based vs ML)
        if self._baseline_responses:
            blocked_count = sum(1 for r in self._baseline_responses if r.blocked_indicators)
            if blocked_count > 0:
                block_consistency = blocked_count / len(self._baseline_responses)
                # Inconsistent blocking suggests ML-based
                if 0.3 < block_consistency < 0.7:
                    confidence += 0.3

        self._baseline_responses.append(features)
        if len(self._baseline_responses) > 10:
            self._baseline_responses = self._baseline_responses[-10:]

        is_ml = confidence >= 0.5
        return is_ml, confidence


class AdversarialHeuristic:
    """Generate adversarial payloads using heuristic methods.

    Uses statistical character frequency, n-gram analysis, and
    pattern-based mutations to generate payloads that may bypass
    ML-based WAFs.
    """

    def __init__(self) -> None:
        self._char_frequency = self._build_common_char_frequency()
        self._common_substitutions = self._build_substitution_patterns()

    def _build_common_char_frequency(self) -> dict[str, float]:
        """Build frequency map of common SQL characters."""
        common_sql_chars = (
            "SELECTFROMWHEREANDORUNIONALLLIMITORDERBYGROUPHAVINGCOUNTSUMAVGMAXMINJOIN"
        )
        counter = Counter(common_sql_chars.lower())
        total = sum(counter.values())
        return {char: count / total for char, count in counter.items()}

    def _build_substitution_patterns(self) -> dict[str, list[str]]:
        """Build character substitution patterns for evasion."""
        return {
            "s": ["$", "5", "§"],
            "e": ["3", "€", "ę"],
            "a": ["@", "4", "æ"],
            "o": ["0", "ø", "ó"],
            "i": ["1", "!", "í"],
            "l": ["1", "|", "ł"],
            "t": ["7", "+", "†"],
            " ": ["/**/", "%20", "\t", "\n"],
        }

    def generate_adversarial_payload(self, payload: str, mutation_strength: float = 0.3) -> str:
        """Generate adversarial payload using heuristic mutations."""
        if mutation_strength <= 0:
            return payload

        result = list(payload)
        mutation_count = int(len(payload) * mutation_strength)

        for _ in range(mutation_count):
            idx = hash(str(_)) % len(result)
            char = result[idx].lower()

            if char in self._common_substitutions:
                substitutions = self._common_substitutions[char]
                sub_idx = hash(str(_)) % len(substitutions)
                result[idx] = substitutions[sub_idx]

        return "".join(result)

    def generate_frequency_based_payload(self, payload: str) -> str:
        """Generate payload with frequency-based character selection."""
        # Sort characters by frequency (less frequent first)
        chars_by_freq = sorted(self._char_frequency.items(), key=lambda x: x[1])

        result = []
        for char in payload:
            char_lower = char.lower()
            if char_lower in self._char_frequency:
                # Occasionally substitute with less frequent character
                if hash(char) % 10 < 3:  # 30% chance
                    freq_chars = [c for c, _ in chars_by_freq[:5]]
                    if freq_chars:
                        result.append(freq_chars[hash(char) % len(freq_chars)])
                    else:
                        result.append(char)
                else:
                    result.append(char)
            else:
                result.append(char)

        return "".join(result)


class PatternAnalyzer:
    """Analyze WAF response patterns for statistical insights."""

    def __init__(self) -> None:
        self._response_history: list[dict[str, Any]] = []
        self._pattern_cache: dict[str, Any] = {}

    def analyze_response(self, response: dict[str, Any]) -> dict[str, Any]:
        """Analyze a single WAF response for patterns."""
        analysis = {
            "blocked": self._is_blocked(response),
            "timing_variance": self._calculate_timing_variance(),
            "pattern_similarity": self._calculate_pattern_similarity(response),
            "anomaly_score": self._calculate_anomaly_score(response),
        }

        self._response_history.append(response)
        if len(self._response_history) > 50:
            self._response_history = self._response_history[-50:]

        return analysis

    def _is_blocked(self, response: dict[str, Any]) -> bool:
        """Determine if response indicates a blocked request."""
        status_code = response.get("status_code", 0)
        body = response.get("text", "").lower()

        # Check status codes
        if status_code in {403, 406, 429, 503}:
            return True

        # Check body for block indicators
        block_indicators = ["blocked", "denied", "forbidden", "waf", "firewall"]
        return any(indicator in body for indicator in block_indicators)

    def _calculate_timing_variance(self) -> float:
        """Calculate variance in response times."""
        if len(self._response_history) < 3:
            return 0.0

        times = [r.get("response_time", 0.0) for r in self._response_history]
        if not times:
            return 0.0

        try:
            return statistics.stdev(times) if len(times) > 1 else 0.0
        except statistics.StatisticsError:
            return 0.0

    def _calculate_pattern_similarity(self, response: dict[str, Any]) -> float:
        """Calculate similarity to previous response patterns."""
        if not self._response_history:
            return 0.0

        current_status = response.get("status_code", 0)
        similar_count = sum(
            1 for r in self._response_history if r.get("status_code") == current_status
        )

        return similar_count / len(self._response_history)

    def _calculate_anomaly_score(self, response: dict[str, Any]) -> float:
        """Calculate anomaly score for response."""
        if not self._response_history:
            return 0.0

        current_time = response.get("response_time", 0.0)
        times = [r.get("response_time", 0.0) for r in self._response_history]

        if not times:
            return 0.0

        try:
            mean_time = statistics.mean(times)
            if mean_time == 0:
                return 0.0

            deviation = abs(current_time - mean_time) / mean_time
            return min(deviation, 1.0)
        except statistics.StatisticsError:
            return 0.0


class BypassGenerator:
    """Generate bypass payloads using statistical methods."""

    def __init__(self) -> None:
        self._adversarial_heuristic = AdversarialHeuristic()
        self._pattern_analyzer = PatternAnalyzer()
        self._successful_mutations: dict[str, int] = defaultdict(int)

    def generate_bypass(
        self,
        session: ScanSession,
        payload: str,
        waf_response: dict[str, Any] | None = None,
    ) -> list[str]:
        """Generate bypass payloads based on WAF response analysis."""
        bypass_candidates = []

        # Analyze WAF response if available
        if waf_response:
            analysis = self._pattern_analyzer.analyze_response(waf_response)

            # If timing variance is high, use frequency-based mutations
            if analysis.get("timing_variance", 0) > 50:
                bypass_candidates.append(
                    self._adversarial_heuristic.generate_frequency_based_payload(payload)
                )

            # If anomaly score is high, use adversarial mutations
            if analysis.get("anomaly_score", 0) > 0.5:
                bypass_candidates.append(
                    self._adversarial_heuristic.generate_adversarial_payload(
                        payload, mutation_strength=0.4
                    )
                )

        # Default bypass strategies
        bypass_candidates.extend(
            [
                self._adversarial_heuristic.generate_adversarial_payload(
                    payload, mutation_strength=0.2
                ),
                self._adversarial_heuristic.generate_adversarial_payload(
                    payload, mutation_strength=0.3
                ),
                self._adversarial_heuristic.generate_frequency_based_payload(payload),
            ]
        )

        return list(set(bypass_candidates))  # Remove duplicates

    def record_success(self, mutation_type: str) -> None:
        """Record successful mutation for future optimization."""
        self._successful_mutations[mutation_type] += 1

    def get_preferred_mutation(self) -> str:
        """Get the most successful mutation type."""
        if not self._successful_mutations:
            return "adversarial_0.3"

        return max(self._successful_mutations.items(), key=lambda x: x[1])[0]


def detect_ml_waf(session: ScanSession, response: dict[str, Any]) -> tuple[bool, float]:
    """Detect if WAF is ML-based using heuristic analysis."""
    detector = MLWAFDetector()
    features = detector.extract_features(response)
    return detector.is_ml_waf(features)


def generate_adversarial_payload(payload: str, mutation_strength: float = 0.3) -> str:
    """Generate adversarial payload using heuristic mutations."""
    heuristic = AdversarialHeuristic()
    return heuristic.generate_adversarial_payload(payload, mutation_strength)


def analyze_waf_pattern(response: dict[str, Any]) -> dict[str, Any]:
    """Analyze WAF response pattern for statistical insights."""
    analyzer = PatternAnalyzer()
    return analyzer.analyze_response(response)
