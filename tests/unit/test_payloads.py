from stealthix.utils import load_payloads, resolve_payloads


def test_payload_counts():
    assert len(load_payloads("sqli")) >= 80
    assert len(load_payloads("error_based")) >= 60
    assert len(load_payloads("union_based")) >= 30
    assert len(load_payloads("time_based")) >= 25
    assert len(load_payloads("nosqli")) >= 50
    assert len(load_payloads("newsql")) >= 25


def test_total_unique_payloads():
    all_payloads: set[str] = set()
    for kind in ["sqli", "error_based", "union_based", "time_based", "stacked", "nosqli", "newsql"]:
        all_payloads.update(load_payloads(kind))
    assert len(all_payloads) >= 200


def test_expanded_payload_catalog_is_substantially_larger():
    expanded: set[str] = set()
    for kind in ["sqli", "error_based", "union_based", "time_based", "stacked", "nosqli", "newsql"]:
        expanded.update(resolve_payloads(kind, expand=True, risk=3))
    assert len(expanded) >= 500
