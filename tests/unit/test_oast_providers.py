from __future__ import annotations

from stealthix.oob.providers import LocalDnsOASTProvider, PassiveOASTProvider, provider_from_env


class FakeListener:
    def __init__(self) -> None:
        self.tokens: list[str] = []

    def wait_for_tokens(self, tokens: list[str], timeout: float) -> dict[str, bool]:
        self.tokens = tokens
        assert timeout == 0.25
        return {token: token == "alpha" for token in tokens}

    def query_log(self, suffix: str | None = None) -> list[dict[str, float | str]]:
        assert suffix == "oast.test"
        return [{"qname": "alpha.oast.test", "timestamp": 123.0}]


def test_passive_provider_builds_hosts_and_unconfirmed_results() -> None:
    provider = PassiveOASTProvider(domain="oast.test")

    assert provider.host_for_token("Alpha") == "alpha.oast.test"
    confirmation = provider.wait_for_tokens(["Alpha"], timeout=0.1)

    assert confirmation.provider == "passive-domain"
    assert confirmation.confirmed == {"alpha": False}
    assert confirmation.interactions == []


def test_local_dns_provider_reports_confirmed_interactions() -> None:
    provider = LocalDnsOASTProvider(domain="oast.test", listener=FakeListener())

    confirmation = provider.wait_for_tokens(["alpha", "beta"], timeout=0.25)

    assert confirmation.provider == "local-dns"
    assert confirmation.confirmed == {"alpha": True, "beta": False}
    assert confirmation.interactions[0].protocol == "dns"
    assert confirmation.interactions[0].token == "alpha"


def test_provider_from_env_selects_passive(monkeypatch) -> None:
    monkeypatch.setenv("STEALTHIX_OOB_DOMAIN", "Example.COM.")
    monkeypatch.delenv("STEALTHIX_OOB_LISTEN", raising=False)

    provider = provider_from_env()

    assert isinstance(provider, PassiveOASTProvider)
    assert provider.domain == "example.com"
