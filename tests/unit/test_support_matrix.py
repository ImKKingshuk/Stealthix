from __future__ import annotations

from stealthix.support_matrix import (
    build_support_matrix,
    get_support_entry,
    render_support_matrix_text,
)


def test_support_matrix_includes_proof_metadata() -> None:
    entry = get_support_entry("mysql")

    assert entry is not None
    assert entry["support_depth"] == "rich"
    assert entry["proof_tier"] == "profile-unit-tested"
    assert entry["fixture_status"] == "unit-tested"
    assert entry["extraction"]["dump"] == "supported"


def test_metadata_only_profiles_are_not_promoted_to_rich() -> None:
    entry = get_support_entry("postgres")

    assert entry is not None
    assert entry["name"] == "postgresql"
    assert entry["extraction"]["dump"] == "supported"
    assert entry["proof_tier"] == "profile-metadata"
    assert entry["fixture_status"] == "metadata-only"
    assert entry["support_depth"] == "moderate"


def test_support_matrix_renderers_expose_proof_tier_fields() -> None:
    matrix = build_support_matrix()
    rendered = render_support_matrix_text(matrix)

    assert matrix["validation"]["proof_tier_labels"]["profile-metadata"]
    assert "proof_tier=" in rendered
    assert "fixture_status=" in rendered
