"""Tests for score calculation."""

from topology_validator.report import calculate_score


def _finding(severity):
    return {"severity": severity, "message": "", "devices": []}


def test_score_empty_is_100_a():
    score = calculate_score([])
    assert score["score"] == 100
    assert score["grade"] == "A"


def test_score_one_critical_is_75_c():
    score = calculate_score([_finding("critical")])
    assert score["score"] == 75
    assert score["grade"] == "C"


def test_score_one_high_is_90_a():
    score = calculate_score([_finding("high")])
    assert score["score"] == 90
    assert score["grade"] == "A"


def test_score_mixed():
    findings = [
        _finding("critical"),  # -25
        _finding("high"),      # -10
        _finding("medium"),    # -4
        _finding("low"),       # -1
    ]
    score = calculate_score(findings)
    assert score["score"] == 60  # 100 - 40
    assert score["grade"] == "D"


def test_score_floors_at_zero():
    findings = [_finding("critical")] * 10  # -250
    score = calculate_score(findings)
    assert score["score"] == 0
    assert score["grade"] == "F"


def test_counts_are_correct():
    findings = [_finding("high")] * 3 + [_finding("low")] * 2
    score = calculate_score(findings)
    assert score["counts"] == {"high": 3, "low": 2}