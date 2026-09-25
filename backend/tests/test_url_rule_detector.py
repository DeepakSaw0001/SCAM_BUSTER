"""
Unit Tests for URL Rule-Based Detection (Phase 02)
"""

import pytest
from app.services.url_rule_detector import evaluate_url_rules


def test_clean_legitimate_url_has_minimal_rules():
    findings = evaluate_url_rules("https://example.com/about")
    # Clean HTTPS site on normal port should have 0 findings
    assert len(findings) == 0


def test_ip_hostname_rule():
    findings = evaluate_url_rules("https://192.168.1.1/index.html")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_IP_HOSTNAME" in rule_ids
    ip_finding = next(f for f in findings if f.rule_id == "RULE_IP_HOSTNAME")
    assert ip_finding.severity == "high"


def test_excessive_subdomains_rule():
    findings = evaluate_url_rules("https://a.b.c.d.example.com/test")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_EXCESSIVE_SUBDOMAINS" in rule_ids


def test_suspicious_keyword_cluster_rule():
    findings = evaluate_url_rules("https://example.com/account/login/verify")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_KEYWORD_PATTERN" in rule_ids
    kw_finding = next(f for f in findings if f.rule_id == "RULE_KEYWORD_PATTERN")
    assert kw_finding.severity == "high"


def test_single_keyword_has_lower_severity():
    findings = evaluate_url_rules("https://example.com/login")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_KEYWORD_SINGLE" in rule_ids
    finding = next(f for f in findings if f.rule_id == "RULE_KEYWORD_SINGLE")
    assert finding.severity == "low"


def test_encoded_obfuscation_rule():
    findings = evaluate_url_rules("https://example.com/page%2e%2e/file%2fadmin")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_ENCODED_OBFUSCATION" in rule_ids


def test_userinfo_spoofing_rule():
    findings = evaluate_url_rules("https://google.com@evil-attacker.com/login")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_USERINFO_SPOOFING" in rule_ids
    assert any(f.severity == "high" for f in findings)


def test_path_redirection_sequence_rule():
    findings = evaluate_url_rules("https://example.com//redirect/evil.com")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_PATH_REDIRECT" in rule_ids


def test_suspicious_tld_rule():
    findings = evaluate_url_rules("https://urgent-verification.xyz/home")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_SUSPICIOUS_TLD" in rule_ids


def test_non_standard_port_rule():
    findings = evaluate_url_rules("https://example.com:8443/api")
    rule_ids = [f.rule_id for f in findings]
    assert "RULE_NON_STANDARD_PORT" in rule_ids


def test_unencrypted_http_rule():
    # Demonstrates that HTTP alone is only a LOW indicator
    findings = evaluate_url_rules("http://example.com/")
    assert len(findings) == 1
    assert findings[0].rule_id == "RULE_UNENCRYPTED_HTTP"
    assert findings[0].severity == "low"
    assert findings[0].score_weight == 10
