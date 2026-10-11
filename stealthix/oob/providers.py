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


@dataclass
class HttpOASTProvider:
    """OAST provider for HTTP/HTTPS callback services (e.g. Interactsh, webhook receivers)."""

    endpoint_url: str
    poll_url: str | None = None
    auth_header: str | None = None
    domain: str = ""
    name: str = "http-oast"

    def __post_init__(self) -> None:
        if not self.domain:
            from urllib.parse import urlparse

            parsed = urlparse(self.endpoint_url)
            self.domain = (parsed.hostname or "oast.internal").lower()

    def host_for_token(self, token: str) -> str:
        return f"{token}.{self.domain}".lower()

    def callback_url_for_token(self, token: str) -> str:
        base = self.endpoint_url.rstrip("/")
        return f"{base}/{token}"

    def wait_for_tokens(self, tokens: list[str], timeout: float) -> OASTConfirmation:
        import json
        import urllib.request
        from urllib.error import URLError

        normalized = [str(token).lower() for token in tokens if str(token).strip()]
        confirmed: dict[str, bool] = dict.fromkeys(normalized, False)
        interactions: list[OASTInteraction] = []
        poll_target = self.poll_url or f"{self.endpoint_url.rstrip('/')}/poll"
        deadline = time.time() + max(0.01, timeout)

        seen_keys: set[tuple[str, str, float, str | None]] = set()

        while True:
            try:
                req = urllib.request.Request(poll_target)
                if self.auth_header:
                    req.add_header("Authorization", self.auth_header)
                req.add_header("User-Agent", "Stealthix-OAST/1.0")
                with urllib.request.urlopen(req, timeout=min(5.0, max(0.5, timeout))) as resp:
                    data = resp.read().decode("utf-8", errors="replace")
                    try:
                        events = json.loads(data)
                        if isinstance(events, list):
                            for event in events:
                                if isinstance(event, dict):
                                    host = str(event.get("host") or event.get("qname") or event.get("url") or "").lower()
                                    raw_proto = str(event.get("protocol") or "http")
                                    matched_token = next((t for t in normalized if t in host or t in str(event)), None)
                                    if matched_token:
                                        confirmed[matched_token] = True
                                    ts = float(event.get("timestamp") or time.time())
                                    key = (raw_proto, host, ts, matched_token)
                                    if key not in seen_keys:
                                        seen_keys.add(key)
                                        interactions.append(
                                            OASTInteraction(
                                                protocol=raw_proto,
                                                token=matched_token,
                                                host=host,
                                                timestamp=ts,
                                                raw={
                                                    str(k): v
                                                    for k, v in event.items()
                                                    if isinstance(v, (str, float, int))
                                                },
                                            )
                                        )
                    except json.JSONDecodeError:
                        pass
            except (URLError, TimeoutError, OSError):
                pass

            if all(confirmed.values()) or time.time() >= deadline:
                break
            time.sleep(min(0.25, max(0.05, timeout / 5)))

        return OASTConfirmation(
            provider=self.name,
            domain=self.domain,
            confirmed=confirmed,
            interactions=interactions,
        )


def provider_from_env() -> OASTProvider | None:
    """Build the configured OAST provider from environment variables."""

    http_endpoint = (os.environ.get("STEALTHIX_OOB_HTTP_URL") or "").strip()
    if http_endpoint:
        poll_url = (os.environ.get("STEALTHIX_OOB_POLL_URL") or "").strip() or None
        auth_header = (os.environ.get("STEALTHIX_OOB_AUTH_HEADER") or "").strip() or None
        explicit_domain = (os.environ.get("STEALTHIX_OOB_DOMAIN") or "").strip().lower().strip(".")
        return HttpOASTProvider(
            endpoint_url=http_endpoint,
            poll_url=poll_url,
            auth_header=auth_header,
            domain=explicit_domain,
        )

    domain = (os.environ.get("STEALTHIX_OOB_DOMAIN") or "").strip().lower().strip(".")
    if not domain:
        return None
    if os.environ.get("STEALTHIX_OOB_LISTEN"):
        return LocalDnsOASTProvider(domain=domain)
    return PassiveOASTProvider(domain=domain)
