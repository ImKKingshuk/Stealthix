from stealthix.core.session import ScanSession, SessionConfig
from stealthix.utils.bypass import apply_waf_bypass


def test_apply_waf_bypass_explicit(monkeypatch):
    class FakeBypass:
        def apply(self, payload: str) -> str:
            return f"X{payload}Y"

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    monkeypatch.setenv("STEALTHIX_WAF_BYPASS", "cloudflare")
    monkeypatch.setattr(
        "stealthix.utils.bypass.load_rust_core", lambda: {"CloudflareBypass": FakeBypass}
    )
    assert apply_waf_bypass(session, "SELECT 1") == "XSELECT 1Y"


def test_apply_waf_bypass_chains_detected_and_generic(monkeypatch):
    class CloudflareBypass:
        def apply(self, payload: str) -> str:
            return f"CF({payload})"

    class PayloadObfuscator:
        def apply(self, payload: str) -> str:
            return f"GEN({payload})"

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["waf"] = ["cloudflare", "imperva"]
    monkeypatch.setattr(
        "stealthix.utils.bypass.load_rust_core",
        lambda: {"CloudflareBypass": CloudflareBypass, "PayloadObfuscator": PayloadObfuscator},
    )

    out = apply_waf_bypass(session, "SELECT 1")
    assert out == "GEN(GEN(CF(SELECT 1)))"
    assert session.metadata["bypass"]["modes"] == ["cloudflare", "imperva", "generic"]


def test_apply_waf_bypass_applies_explicit_tamper_pipeline_and_headers(monkeypatch):
    monkeypatch.setattr("stealthix.utils.bypass.load_rust_core", lambda: {})
    session = ScanSession(
        SessionConfig(
            base_url="http://example.test", tamper_pipeline=["space2comment", "xforwardedfor"]
        )
    )

    transformed = apply_waf_bypass(session, "UNION SELECT")

    assert transformed == "UNION/**/SELECT"
    assert session.runtime["tamper_headers_override"]["X-Forwarded-For"]
    assert session.metadata["bypass"]["pipeline"] == ["space2comment", "xforwardedfor"]


def test_apply_waf_bypass_auto_selects_vendor_profile(monkeypatch):
    monkeypatch.setattr("stealthix.utils.bypass.load_rust_core", lambda: {})
    session = ScanSession(
        SessionConfig(base_url="http://example.test", tamper_pipeline=["space2comment"])
    )
    session.metadata["waf"] = {"detected": "cloudflare"}

    transformed = apply_waf_bypass(session, "SELECT '1'")

    assert transformed != "SELECT '1'"
    assert session.metadata["bypass"]["vendor"] == "cloudflare"
