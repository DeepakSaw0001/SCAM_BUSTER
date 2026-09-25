"""
Unit Tests for ScamBuster Risk Engine Foundation (Phase 02)
"""

import pytest
from app.services.url_rule_detector import RuleFinding
from app.risk_engine.scorer import calculate_risk_score
from app.risk_engine.categories import determine_categories
from app.risk_engine.explanations import generate_summary, generate_recommendation, generate_reasons


def test_insufficient_evidence_unknown_state():
    score, level, confidence = calculate_risk_score([], has_sufficient_evidence=False)
    assert score == 0
    assert level == "unknown"
    assert confidence == 0.0

    summary = generate_summary("unknown", [], "https://empty.test")
    assert "Insufficient evidence" in summary


def test_clean_baseline_evidence():
    score, level, confidence = calculate_risk_score([], has_sufficient_evidence=True)
    assert score == 0
    assert level == "very_low"
    assert confidence >= 0.80

    categories = determine_categories([])
    assert "benign_baseline" in categories

    reasons = generate_reasons([])
    assert len(reasons) == 1
    assert "No suspicious" in reasons[0]


def test_low_evidence():
    findings = [
        RuleFinding(
            rule_id="RULE_UNENCRYPTED_HTTP",
            name="Unencrypted HTTP Transport",
            severity="low",
            score_weight=10,
            description="HTTP unencrypted",
            evidence="http://",
        )
    ]
    score, level, confidence = calculate_risk_score(findings)
    assert score <= 39
    assert level in ("very_low", "low")
    assert confidence > 0.50


def test_medium_evidence():
    findings = [
        RuleFinding(
            rule_id="RULE_URL_LENGTH",
            name="Excessive URL Length",
            severity="medium",
            score_weight=20,
            description="Long URL",
            evidence="120 chars",
        ),
        RuleFinding(
            rule_id="RULE_SUSPICIOUS_TLD",
            name="High-Risk Top-Level Domain",
            severity="medium",
            score_weight=20,
            description="uses .xyz",
            evidence=".xyz",
        ),
    ]
    score, level, confidence = calculate_risk_score(findings)
    assert 40 <= score <= 59
    assert level == "medium"
    assert confidence >= 0.70


def test_high_evidence():
    findings = [
        RuleFinding(
            rule_id="RULE_IP_HOSTNAME",
            name="IP-based Hostname",
            severity="high",
            score_weight=35,
            description="Raw IP host",
            evidence="192.168.1.1",
        ),
        RuleFinding(
            rule_id="RULE_KEYWORD_PATTERN",
            name="Suspicious Keyword Pattern",
            severity="medium",
            score_weight=25,
            description="Contains login/update",
            evidence="login, update",
        ),
    ]
    score, level, confidence = calculate_risk_score(findings)
    assert 60 <= score <= 79
    assert level == "high"
    assert confidence >= 0.75

    recommendation = generate_recommendation(level, findings)
    assert "Avoid entering passwords" in recommendation or "caution" in recommendation.lower()


def test_critical_evidence():
    findings = [
        RuleFinding(
            rule_id="RULE_IP_HOSTNAME",
            name="IP-based Hostname",
            severity="high",
            score_weight=35,
            description="Raw IP",
            evidence="192.168.1.1",
        ),
        RuleFinding(
            rule_id="RULE_USERINFO_SPOOFING",
            name="Userinfo Host Spoofing",
            severity="high",
            score_weight=35,
            description="@ host spoofing",
            evidence="@",
        ),
        RuleFinding(
            rule_id="RULE_KEYWORD_PATTERN",
            name="Suspicious Keyword Pattern",
            severity="high",
            score_weight=25,
            description="credential harvest",
            evidence="verify, login, password",
        ),
    ]
    score, level, confidence = calculate_risk_score(findings)
    assert score >= 80
    assert level == "critical"
    assert confidence >= 0.80

    categories = determine_categories(findings)
    assert "potential_phishing" in categories
    assert "suspicious_infrastructure" in categories
