from __future__ import annotations

from unittest.mock import patch

from stealthix.evasion.polymorphic import (
    _DEFAULT_ENCODING_OPERATIONS,
    PolymorphicEncoder,
    _py_fallback_tamper,
)


def test_py_fallback_tamper_operations() -> None:
    text = "SELECT * FROM users WHERE id = 1"

    url_enc = _py_fallback_tamper("url_encode", text)
    assert "%20" in url_enc or "%2A" in url_enc

    comment_enc = _py_fallback_tamper("space_to_comment", text)
    assert "/**/" in comment_enc
    assert " " not in comment_enc

    plus_enc = _py_fallback_tamper("space_to_plus", text)
    assert "+" in plus_enc
    assert " " not in plus_enc

    hex_enc = _py_fallback_tamper("hex_encode", "ABC")
    assert hex_enc == "%41%42%43"

    b64_enc = _py_fallback_tamper("base64_encode", "admin")
    assert b64_enc == "YWRtaW4="

    html_enc = _py_fallback_tamper("html_encode", "<script>")
    assert html_enc == "&lt;script&gt;"


def test_polymorphic_encoder_without_rust_core() -> None:
    with patch("stealthix.evasion.polymorphic.load_rust_core", return_value={}):
        encoder = PolymorphicEncoder()
        assert encoder._available_operations == list(_DEFAULT_ENCODING_OPERATIONS)

        chain = encoder.generate_chain(length=3)
        assert len(chain.operations) == 3
        assert all(op in _DEFAULT_ENCODING_OPERATIONS for op in chain.operations)

        mutated = encoder.mutate_chain(chain)
        assert len(mutated.operations) >= 2

        encoded = encoder.apply_chain(mutated, "admin' OR 1=1--")
        assert isinstance(encoded, str)
        assert len(encoded) > 0
