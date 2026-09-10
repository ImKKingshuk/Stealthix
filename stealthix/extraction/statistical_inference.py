"""Statistical frequency analysis for blind inference optimization."""

from __future__ import annotations

from collections import Counter
from typing import Any


class StatisticalPredictor:
    """Statistical character prediction based on frequency analysis."""

    # Common character frequency tables for different contexts
    COMMON_CHARS = "etaoinshrdlcumwfgypbvkjxqz"
    COMMON_HEX = "0123456789abcdef"
    COMMON_DIGITS = "0123456789"
    COMMON_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    COMMON_EMAIL = "abcdefghijklmnopqrstuvwxyz0123456789@._-"
    COMMON_URL = "abcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+,;="

    # Common bigrams (2-character sequences) in English
    COMMON_BIGRAMS = [
        "th",
        "he",
        "in",
        "er",
        "an",
        "re",
        "on",
        "at",
        "en",
        "nd",
        "ti",
        "es",
        "or",
        "te",
        "of",
        "ed",
        "is",
        "it",
        "al",
        "ar",
        "st",
        "to",
        "nt",
        "ng",
        "se",
        "ha",
        "as",
        "ou",
        "et",
    ]

    # Common trigrams (3-character sequences) in English
    COMMON_TRIGRAMS = [
        "the",
        "and",
        "ing",
        "ent",
        "ion",
        "ter",
        "ate",
        "eve",
        "her",
        "for",
        "ith",
        "tin",
        "est",
        "ers",
        "his",
        "are",
        "ver",
        "not",
    ]

    def __init__(self, context: str = "") -> None:
        """Initialize predictor with optional context string."""
        self.context = context.lower()
        self.char_frequency = self._build_char_frequency()
        self.bigram_frequency = self._build_ngram_frequency(2)
        self.trigram_frequency = self._build_ngram_frequency(3)

    def _build_char_frequency(self) -> Counter[str]:
        """Build character frequency from context."""
        if not self.context:
            return Counter(self.COMMON_CHARS)
        return Counter(self.context)

    def _build_ngram_frequency(self, n: int) -> Counter[str]:
        """Build n-gram frequency from context."""
        if not self.context or len(self.context) < n:
            if n == 2:
                return Counter(self.COMMON_BIGRAMS)
            if n == 3:
                return Counter(self.COMMON_TRIGRAMS)
            return Counter()

        ngrams = []
        for i in range(len(self.context) - n + 1):
            ngrams.append(self.context[i : i + n])
        return Counter(ngrams)

    def predict_next_char(self, char_set: str | None = None) -> list[str]:
        """Predict likely next characters based on frequency analysis."""
        if char_set:
            valid_chars = [c for c in self.COMMON_CHARS if c in char_set]
        else:
            valid_chars = list(self.COMMON_CHARS)

        # Use character frequency from context if available
        if self.context:
            last_char = self.context[-1]
            # Find bigrams starting with last character
            bigram_candidates = [bg[1] for bg in self.COMMON_BIGRAMS if bg[0] == last_char]
            if bigram_candidates:
                valid_chars = bigram_candidates + [
                    c for c in valid_chars if c not in bigram_candidates
                ]

        # Sort by frequency (higher frequency first)
        if self.context:
            char_freq = {c: self.char_frequency.get(c, 0) for c in valid_chars}
            sorted_chars = sorted(valid_chars, key=lambda c: char_freq[c], reverse=True)
        else:
            sorted_chars = valid_chars

        return sorted_chars

    def predict_string_completion(self, prefix: str, max_length: int = 10) -> list[str]:
        """Predict likely completions for a given prefix."""
        if not prefix:
            return []

        prefix_lower = prefix.lower()
        completions = []

        # Find words in context that start with prefix
        if self.context:
            words = self.context.split()
            for word in words:
                if word.startswith(prefix_lower):
                    completions.append(word)

        # If no completions from context, use common patterns
        if not completions:
            # Generate completions based on common bigrams
            if len(prefix) == 1:
                for bigram in self.COMMON_BIGRAMS:
                    if bigram[0] == prefix_lower:
                        completions.append(prefix_lower + bigram[1])

        # Remove duplicates and limit
        completions = list(dict.fromkeys(completions))
        return completions[:max_length]

    def get_char_set_by_type(self, data_type: str) -> str:
        """Get character set based on data type."""
        type_map = {
            "hex": self.COMMON_HEX,
            "digits": self.COMMON_DIGITS,
            "base64": self.COMMON_BASE64,
            "email": self.COMMON_EMAIL,
            "url": self.COMMON_URL,
            "default": self.COMMON_CHARS,
        }
        return type_map.get(data_type.lower(), self.COMMON_CHARS)

    def rank_chars_by_probability(self, chars: list[str], char_set: str | None = None) -> list[str]:
        """Rank characters by probability based on frequency analysis."""
        if char_set:
            valid_chars = [c for c in chars if c in char_set]
        else:
            valid_chars = chars

        if not valid_chars:
            return []

        # Sort by frequency (higher frequency first)
        if self.context:
            char_freq = {c: self.char_frequency.get(c, 0) for c in valid_chars}
            sorted_chars = sorted(valid_chars, key=lambda c: char_freq[c], reverse=True)
        else:
            # Use default character order
            sorted_chars = sorted(
                valid_chars,
                key=lambda c: self.COMMON_CHARS.index(c) if c in self.COMMON_CHARS else 999,
            )

        return sorted_chars

    def estimate_length_range(self, sample_data: list[str]) -> tuple[int, int]:
        """Estimate likely length range based on sample data."""
        if not sample_data:
            return (1, 128)

        lengths = [len(s) for s in sample_data if s]
        if not lengths:
            return (1, 128)

        avg_length = sum(lengths) / len(lengths)
        min_length = max(1, int(avg_length * 0.5))
        max_length = min(128, int(avg_length * 2))

        return (min_length, max_length)


def build_predictor_from_samples(samples: list[str]) -> StatisticalPredictor:
    """Build a statistical predictor from sample data."""
    combined = " ".join(samples)
    return StatisticalPredictor(context=combined)


def get_optimized_search_order(target: str, char_set: str | None = None) -> list[int]:
    """Get optimized search order for binary search based on character frequency."""
    predictor = StatisticalPredictor(context=target)
    chars = list(predictor.COMMON_CHARS)

    if char_set:
        chars = [c for c in chars if c in char_set]

    # Rank characters by frequency
    ranked = predictor.rank_chars_by_probability(chars, char_set)

    # Convert to ASCII codes
    return [ord(c) for c in ranked]
