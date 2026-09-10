"""Out-of-band application security testing providers.

The detection engine should not care whether callbacks are observed through the
local DNS listener, a hosted OAST service, or a future Interactsh-compatible
client. This module provides a small provider boundary and keeps the current
environment-driven behavior backward compatible.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from typing import Protocol

from stealthix.oob.dns_listener import DnsCallbackListener, get_global_listener


@dataclass(frozen=True)
class OASTInteraction:
    """Single observed OAST interaction."""

    protocol: str
    token: str | None
    host: str
    timestamp: float
    raw: dict[str, str | float] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "protocol": self.protocol,
            "token": self.token,
            "host": self.host,
            "timestamp": self.timestamp,
            "raw": dict(self.raw),
        }


@dataclass(frozen=True)
class OASTConfirmation:
    """Confirmed callback state for a batch of OAST tokens."""

    provider: str
    domain: str
    confirmed: dict[str, bool]
    interactions: list[OASTInteraction] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "domain": self.domain,
            "confirmed": dict(self.confirmed),
            "interactions": [item.to_dict() for item in self.interactions],
        }


class OASTProvider(Protocol):
    """Provider contract used by injection engines."""

    name: str
    domain: str

    def host_for_token(self, token: str) -> str:
        """Return a callback host for a token."""

    def wait_for_tokens(self, tokens: list[str], timeout: float) -> OASTConfirmation:
        """Wait for token callbacks and return confirmation evidence."""


@dataclass
class PassiveOASTProvider:
    """Provider for externally monitored domains.

    This keeps compatibility with `STEALTHIX_OOB_DOMAIN` even when Stealthix is
    not running a listener itself. It records attempted callback hosts but cannot
    confirm interactions.
    """

    domain: str
    name: str = "passive-domain"

    def host_for_token(self, token: str) -> str:
        return f"{token}.{self.domain}".lower()

    def wait_for_tokens(self, tokens: list[str], timeout: float) -> OASTConfirmation:
        del timeout
        normalized = [str(token).lower() for token in tokens if str(token).strip()]
        return OASTConfirmation(
            provider=self.name,
            domain=self.domain,
            confirmed=dict.fromkeys(normalized, False),
            interactions=[],
        )


@dataclass
class LocalDnsOASTProvider(PassiveOASTProvider):
    """OAST provider backed by the built-in DNS callback listener."""

    listener: DnsCallbackListener | None = None
    name: str = "local-dns"

    def __post_init__(self) -> None:
        if self.listener is None:
            host = os.environ.get("STEALTHIX_OOB_LISTENER_HOST", "127.0.0.1")
            port = int(os.environ.get("STEALTHIX_OOB_LISTENER_PORT", "53535"))
            self.listener = get_global_listener(host=host, port=port)

    def wait_for_tokens(self, tokens: list[str], timeout: float) -> OASTConfirmation:
        normalized = [str(token).lower() for token in tokens if str(token).strip()]
        listener = self.listener
        if listener is None:
            return super().wait_for_tokens(normalized, timeout)
        confirmed = listener.wait_for_tokens(normalized, timeout=timeout)
        events = listener.query_log(suffix=self.domain)
        interactions: list[OASTInteraction] = []
        for event in events:
            qname = str(event.get("qname") or "").lower()
            matched_token = next((token for token in normalized if token in qname), None)
            interactions.append(
                OASTInteraction(
                    protocol="dns",
                    token=matched_token,
                    host=qname,
                    timestamp=float(event.get("timestamp") or time.time()),
                    raw={str(key): value for key, value in event.items()},
                )
            )
        return OASTConfirmation(
            provider=self.name,
            domain=self.domain,
            confirmed=confirmed,
            interactions=interactions,
        )


def provider_from_env() -> OASTProvider | None:
    """Build the configured OAST provider from environment variables."""

    domain = (os.environ.get("STEALTHIX_OOB_DOMAIN") or "").strip().lower().strip(".")
    if not domain:
        return None
    if os.environ.get("STEALTHIX_OOB_LISTEN"):
        return LocalDnsOASTProvider(domain=domain)
    return PassiveOASTProvider(domain=domain)
