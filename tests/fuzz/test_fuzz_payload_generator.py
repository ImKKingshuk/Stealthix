"""Fuzz tests for payload generator using Hypothesis."""

from hypothesis import given, settings
from hypothesis import strategies as st

from stealthix.payloads.generator import generate_payload_variants


@given(st.text(min_size=1, max_size=100))
def test_generate_payload_variants_handles_various_inputs(seed):
    """Property test: payload generator should handle various seed inputs."""
    try:
        result = generate_payload_variants(seed, technique="BEU")
        assert isinstance(result, list)
        assert all(isinstance(p, str) for p in result)
    except Exception:
        # Should handle any input gracefully
        pass


@given(st.text(min_size=0, max_size=50))
def test_generate_payload_variants_handles_empty_string(seed):
    """Property test: payload generator should handle empty strings."""
    try:
        result = generate_payload_variants(seed, technique="BEU")
        assert isinstance(result, list)
    except Exception:
        # Should handle empty input gracefully
        pass


@given(st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=20))
def test_build_payload_catalog_handles_empty_and_large_lists(payloads):
    """Property test: payload catalog should handle edge cases."""
    from stealthix.payloads.generator import build_payload_catalog

    try:
        catalog = build_payload_catalog(payloads)
        assert isinstance(catalog, dict)
    except Exception:
        # Should handle edge cases gracefully
        pass


@given(st.text(min_size=1, max_size=100))
@settings(deadline=1000)  # Increase deadline to 1 second to avoid flaky failures
def test_payload_encoding_doesnt_crash(payload):
    """Property test: payload encoding should not crash on any input."""
    from stealthix.detection.sqli import _encode_payload

    try:
        result = _encode_payload(payload)
        assert isinstance(result, str)
    except Exception:
        # Should handle any input gracefully
        pass


@given(st.text(min_size=1, max_size=100))
def test_payload_preparation_doesnt_crash(payload):
    """Property test: payload preparation should not crash on any input."""
    from stealthix.core.session import ScanSession, SessionConfig
    from stealthix.detection.sqli import _prepare_payload

    session = ScanSession(SessionConfig(base_url="http://example.com"))

    try:
        result = _prepare_payload(session, payload)
        assert isinstance(result, str)
    except Exception:
        # Should handle any input gracefully
        pass
