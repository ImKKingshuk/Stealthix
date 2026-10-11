"""
Global rate limiter with token-bucket algorithm and per-host tracking.

This module provides thread-safe rate limiting for HTTP requests to prevent
request flooding and respect target server capacity.
"""

from __future__ import annotations

import os
import threading
import time
from collections import defaultdict
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger(__name__)


class TokenBucket:
    """Token bucket for rate limiting with refill logic."""

    def __init__(self, rate: float, capacity: int):
        """
        Initialize token bucket.

        Args:
            rate: Tokens per second (refill rate)
            capacity: Maximum number of tokens (burst size)
        """
        self.rate = max(0.001, float(rate))
        self.capacity = max(1, int(capacity))
        self.tokens = float(self.capacity)
        self.last_refill = time.time()
        self.lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """
        Consume tokens if available.

        Args:
            tokens: Number of tokens to consume

        Returns:
            True if tokens were consumed, False if insufficient tokens
        """
        with self.lock:
            now = time.time()
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            if elapsed > 0:
                refill = elapsed * self.rate
                self.tokens = min(self.capacity, self.tokens + refill)
                self.last_refill = now

            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            return False

    def wait_time(self, tokens: int = 1) -> float:
        """
        Calculate time to wait for tokens to be available.

        Args:
            tokens: Number of tokens needed

        Returns:
            Seconds to wait (0 if tokens available now)
        """
        with self.lock:
            now = time.time()
            elapsed = now - self.last_refill
            if elapsed > 0:
                refill = elapsed * self.rate
                self.tokens = min(self.capacity, self.tokens + refill)
                self.last_refill = now

            if self.tokens >= tokens:
                return 0.0
            return (tokens - self.tokens) / self.rate


class GlobalRateLimiter:
    """Global rate limiter with per-host tracking."""

    def __init__(
        self,
        default_rate: float | None = None,
        default_burst: int | None = None,
    ):
        """
        Initialize global rate limiter.

        Args:
            default_rate: Default requests per second (from env or 10)
            default_burst: Default burst size (from env or 5)
        """
        self.default_rate = max(
            0.001,
            float(default_rate or os.environ.get("STEALTHIX_RATE_LIMIT_RPS", "10")),
        )
        self.default_burst = max(
            1,
            int(default_burst or os.environ.get("STEALTHIX_RATE_LIMIT_BURST", "5")),
        )
        self.buckets: dict[str, TokenBucket] = defaultdict(
            lambda: TokenBucket(self.default_rate, self.default_burst)
        )
        self.lock = threading.Lock()

    def get_bucket(self, host: str) -> TokenBucket:
        """
        Get or create token bucket for host.

        Args:
            host: Target hostname

        Returns:
            TokenBucket for the host
        """
        with self.lock:
            if host not in self.buckets:
                self.buckets[host] = TokenBucket(self.default_rate, self.default_burst)
            return self.buckets[host]

    def acquire(self, url: str, tokens: int = 1) -> bool:
        """
        Try to acquire tokens for a request.

        Args:
            url: Target URL
            tokens: Number of tokens to consume

        Returns:
            True if tokens acquired, False if rate limited
        """
        host = urlparse(url).hostname or url
        bucket = self.get_bucket(host)
        acquired = bucket.consume(tokens)

        if not acquired:
            logger.warning(
                "rate_limit_exceeded",
                host=host,
                url=url,
                available_tokens=bucket.tokens,
                requested_tokens=tokens,
            )

        return acquired

    def wait_time(self, url: str, tokens: int = 1) -> float:
        """
        Get wait time for a request.

        Args:
            url: Target URL
            tokens: Number of tokens needed

        Returns:
            Seconds to wait (0 if available now)
        """
        host = urlparse(url).hostname or url
        bucket = self.get_bucket(host)
        return bucket.wait_time(tokens)

    def set_limit(self, host: str, rate: float, burst: int) -> None:
        """
        Set custom rate limit for a host.

        Args:
            host: Target hostname
            rate: Requests per second
            burst: Burst size
        """
        with self.lock:
            self.buckets[host] = TokenBucket(rate, burst)
            logger.info(
                "rate_limit_set",
                host=host,
                rate=rate,
                burst=burst,
            )

    def reset(self, host: str | None = None) -> None:
        """
        Reset rate limit for a host or all hosts.

        Args:
            host: Specific host to reset, or None to reset all
        """
        with self.lock:
            if host:
                if host in self.buckets:
                    del self.buckets[host]
                    logger.info("rate_limit_reset", host=host)
            else:
                self.buckets.clear()
                logger.info("rate_limit_reset_all")


# Global singleton instance
_global_limiter: GlobalRateLimiter | None = None
_limiter_lock = threading.Lock()


def get_rate_limiter() -> GlobalRateLimiter:
    """Get global rate limiter singleton."""
    global _global_limiter
    if _global_limiter is None:
        with _limiter_lock:
            if _global_limiter is None:
                _global_limiter = GlobalRateLimiter()
    return _global_limiter


def reset_rate_limiter() -> None:
    """Reset global rate limiter (for testing)."""
    global _global_limiter
    with _limiter_lock:
        _global_limiter = None
