from stealthix.core.engine import Finding, ScanResult
from stealthix.reporting.scoring import score_cvss, score_cvss_breakdown, score_result


def test_cvss_score():
    score = score_cvss(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
    )
    assert score >= 8.0


def test_score_result():
    result = ScanResult(
        target="http://example.com",
        findings=[Finding(kind="sqli", target="http://example.com?id=1")],
    )
    scores = score_result(result)
    assert scores["highest"] >= 0
    assert "risk_index" in scores


def test_score_cvss_breakdown_handles_nested_metric_sets():
    score = score_cvss_breakdown(
        {
            "AV": "N",
            "AC": "L",
            "PR": "N",
            "UI": "N",
            "S": "U",
            "C": "H",
            "I": "H",
            "A": "H",
            "temporal": {"E": "F", "RL": "O", "RC": "C"},
            "environmental": {"CR": "H", "IR": "M", "AR": "M", "MC": "H", "MI": "H", "MA": "L"},
        }
    )
    assert score["environmental"] > 0
    assert score["score"] == score["environmental"]
