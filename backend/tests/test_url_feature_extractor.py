"""
Unit Tests for URL Feature Extraction (Phase 02)
"""

import pytest
from app.services.url_feature_extractor import extract_url_features, UrlFeatures


def test_simple_url_features():
    feats = extract_url_features("https://example.com/")
    assert isinstance(feats, UrlFeatures)
    assert feats.uses_https is True
    assert feats.has_ip_hostname is False
    assert feats.subdomain_count == 0
    assert feats.suspicious_keyword_count == 0
    assert feats.has_port is False


def test_long_url_features():
    long_url = "https://example.com/path/to/resource/" + ("sub/" * 10)
    feats = extract_url_features(long_url)
    assert feats.url_length == len(long_url)
    assert feats.path_depth >= 10
    assert feats.number_of_slashes >= 12


def test_url_with_query_params():
    url = "https://example.com/search?q=cybersecurity&filter=recent&page=2"
    feats = extract_url_features(url)
    assert feats.query_parameter_count == 3
    assert feats.number_of_question_marks == 1
    assert feats.number_of_equals == 3


def test_url_with_subdomains():
    url = "https://account.security.verify.example.com/dashboard"
    feats = extract_url_features(url)
    # account, security, verify -> 3 subdomains
    assert feats.subdomain_count >= 3
    assert feats.number_of_dots >= 4


def test_ip_based_url():
    url = "http://192.168.1.1:8080/admin"
    feats = extract_url_features(url)
    assert feats.has_ip_hostname is True
    assert feats.uses_https is False
    assert feats.has_port is True
    assert feats.subdomain_count == 0


def test_url_with_suspicious_keywords():
    url = "https://secure-login.bank-update.com/verify/password/confirm"
    feats = extract_url_features(url)
    assert feats.suspicious_keyword_count >= 4
    for expected in ["login", "secure", "bank", "update", "verify", "password", "confirm"]:
        assert expected in feats.matched_keywords
