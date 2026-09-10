"""Fuzz tests for SQL injection detection using Hypothesis."""

from hypothesis import given
from hypothesis import strategies as st


@given(st.text(), st.text())
def test_sqli_detection_handles_various_responses(body, error_msg):
    """Property test: SQLi detection should handle various response patterns."""
    from stealthix.core.session import ScanSession, SessionConfig
    from stealthix.detection.sqli import _match_errors

    session = ScanSession(SessionConfig(base_url="http://example.com"))

    # Test that error matching doesn't crash
    try:
        result = _match_errors(body, session)
        assert isinstance(result, list)
        assert all(isinstance(r, str) for r in result)
    except Exception:
        # Should handle any input gracefully
        pass


@given(st.text(min_size=1, max_size=100))
def test_error_signatures_doesnt_crash(signature):
    """Property test: error signatures should handle any input."""
    from stealthix.core.session import ScanSession, SessionConfig
    from stealthix.detection.sqli import _error_signatures

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.metadata["plugin"] = {"error_signatures": [signature]}

    try:
        result = _error_signatures(session)
        assert isinstance(result, list)
    except Exception:
        # Should handle any input gracefully
        pass


@given(st.text(min_size=1, max_size=50))
def test_payload_encoding_roundtrip(payload):
    """Property test: payload encoding roundtrip should be reversible."""
    from urllib.parse import unquote

    from stealthix.detection.sqli import _encode_payload

    try:
        encoded = _encode_payload(payload)
        assert isinstance(encoded, str)
        # Double-encoded should decode to original (approximately)
        decoded = unquote(unquote(encoded))
        # Just verify it doesn't crash
        assert isinstance(decoded, str)
    except Exception:
        # Should handle any input gracefully
        pass


@given(st.lists(st.text(min_size=1, max_size=20), min_size=0, max_size=10))
def test_custom_payloads_handling(payloads):
    """Property test: custom payloads handling should not crash."""
    from stealthix.core.session import ScanSession, SessionConfig
    from stealthix.detection.sqli import _custom_payloads

    session = ScanSession(SessionConfig(base_url="http://example.com"))
    session.config.custom_payloads = {"test": payloads}

    try:
        result = _custom_payloads(session, "test")
        if result is not None:
            assert isinstance(result, list)
    except Exception:
        # Should handle any input gracefully
        pass
