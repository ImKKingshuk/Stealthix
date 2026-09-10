"""Unit tests for payload precompilation cache."""

from __future__ import annotations

import pytest

from stealthix.utils.payloads import (
    clear_payload_cache,
    expand_payloads,
    get_cache_stats,
    resolve_payloads,
)


class TestPayloadCache:
    """Test payload precompilation cache."""

    def setup_method(self) -> None:
        """Clear cache before each test."""
        clear_payload_cache()

    def test_expand_payloads_cache_hit(self) -> None:
        """Test that expand_payloads uses cache."""
        # First call - cache miss
        payloads1 = expand_payloads("sqli", ("' OR '1'='1",), max_payloads=10)
        stats1 = get_cache_stats()
        assert stats1["misses"] == 1
        assert stats1["hits"] == 0

        # Second call - cache hit
        payloads2 = expand_payloads("sqli", ("' OR '1'='1",), max_payloads=10)
        stats2 = get_cache_stats()
        assert stats2["misses"] == 1
        assert stats2["hits"] == 1

        # Results should be identical
        assert payloads1 == payloads2

    def test_expand_payloads_cache_different_params(self) -> None:
        """Test that different parameters result in cache misses."""
        # First call
        expand_payloads("sqli", ("' OR '1'='1",), max_payloads=10)
        stats1 = get_cache_stats()

        # Different max_payloads - cache miss
        expand_payloads("sqli", ("' OR '1'='1",), max_payloads=20)
        stats2 = get_cache_stats()
        assert stats2["misses"] == stats1["misses"] + 1

    def test_expand_payloads_cache_clear(self) -> None:
        """Test cache clear function."""
        # Populate cache
        expand_payloads("sqli", ("' OR '1'='1",), max_payloads=10)
        stats1 = get_cache_stats()
        assert stats1["currsize"] > 0

        # Clear cache
        clear_payload_cache()
        stats2 = get_cache_stats()
        assert stats2["currsize"] == 0
        assert stats2["hits"] == 0
        assert stats2["misses"] == 0

    def test_get_cache_stats(self) -> None:
        """Test cache stats function."""
        stats = get_cache_stats()
        assert "hits" in stats
        assert "misses" in stats
        assert "maxsize" in stats
        assert "currsize" in stats
        assert stats["maxsize"] > 0

    def test_resolve_payloads_uses_cache(self) -> None:
        """Test that resolve_payloads uses expand_payloads cache."""
        # First call
        resolve_payloads("sqli", expand=True, max_payloads=10)
        stats1 = get_cache_stats()

        # Second call with same params
        resolve_payloads("sqli", expand=True, max_payloads=10)
        stats2 = get_cache_stats()

        # Should have cache hits
        assert stats2["hits"] > stats1["hits"]

    def test_custom_payloads_bypass_cache(self) -> None:
        """Test that custom payloads bypass cache."""
        custom = ["custom payload 1", "custom payload 2"]
        payloads = resolve_payloads("sqli", custom_payloads=custom, expand=False)
        assert len(payloads) == 2
        assert "custom payload 1" in payloads

    def test_cache_size_limit(self) -> None:
        """Test that cache respects size limit."""
        # Clear cache first
        clear_payload_cache()

        # Make multiple calls with different parameters
        for i in range(150):
            expand_payloads("sqli", (f"payload-{i}",), max_payloads=10)

        stats = get_cache_stats()
        # Cache should be limited to maxsize (default 128)
        assert stats["currsize"] <= stats["maxsize"]
