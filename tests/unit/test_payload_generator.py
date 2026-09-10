from stealthix.payloads.generator import build_payload_catalog, generate_payload_variants
from stealthix.payloads.nosql_advanced import get_advanced_payloads, get_backend_names
from stealthix.utils.payloads import load_payloads, resolve_payloads


def test_generate_payload_variants_produces_diverse_sql_mutations():
    variants = generate_payload_variants(
        "SELECT 1 FROM users WHERE 1=1",
        family="sqli",
        max_variants=14,
        max_depth=1,
    )
    payloads = [variant.payload for variant in variants]

    assert payloads[0] == "SELECT 1 FROM users WHERE 1=1"
    assert any("SeLe" in payload or "sElE" in payload for payload in payloads)
    assert any("/**/" in payload for payload in payloads)
    assert any("\t" in payload or "\n" in payload or "\x0b" in payload for payload in payloads)
    assert any(payload.startswith("(") and payload.endswith(")") for payload in payloads)


def test_build_payload_catalog_expands_beyond_seed_count():
    seeds = load_payloads("sqli")[:6]
    catalog = build_payload_catalog("sqli", seeds, max_payloads=40)

    assert len(catalog) == 40
    assert len(set(catalog)) == 40


def test_resolve_payloads_applies_risk_budget_and_backend_advanced_payloads():
    low_risk = resolve_payloads("nosqli", expand=True, risk=1, advanced_backend="mongodb")
    high_risk = resolve_payloads("nosqli", expand=True, risk=3, advanced_backend="mongodb")
    redis_catalog = resolve_payloads(
        "nosqli",
        custom_payloads=get_advanced_payloads("redis"),
        expand=True,
        risk=2,
        include_advanced=False,
    )

    assert len(low_risk) < len(high_risk)
    assert any("$jsonSchema" in payload or "$where" in payload for payload in high_risk)
    assert any("PING" in payload or "INFO" in payload for payload in redis_catalog)
    assert "mongodb" in get_backend_names()
