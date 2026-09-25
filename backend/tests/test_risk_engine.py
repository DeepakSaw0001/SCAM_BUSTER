"""
Unit Tests for ScamBuster Risk Fusion Engine
"""

import pytest
from app.risk_engine.engine import fuse_risk_analysis


def test_fuse_benign_url():
    heuristic_res = {"score": 0, "indicators": [], "details": {}}
    ml_res = {
        "prediction": "benign",
        "probability": 0.99,
        "malicious_probability": 0.01,
        "model": "URL Features + Random Forest",
        "model_version": "1.0.0",
        "features_used": 17,
    }
    result = fuse_risk_analysis("url", "https://google.com", heuristic_res, ml_res)
    assert result.composite_risk_score < 35
    assert result.risk_level == "SAFE"
    assert result.ml_metadata is not None
    assert result.ml_metadata.prediction == "benign"


def test_fuse_malicious_url_high_ml_and_heuristic():
    heuristic_res = {
        "score": 60,
        "indicators": [
            {
                "name": "Direct IP Address Hostname",
                "severity": "HIGH",
                "description": "Raw IP host",
                "evidence": "192.168.1.1",
            }
        ],
        "details": {},
    }
    ml_res = {
        "prediction": "malicious",
        "probability": 0.95,
        "malicious_probability": 0.95,
        "model": "URL Features + Random Forest",
        "model_version": "1.0.0",
        "features_used": 17,
    }
    result = fuse_risk_analysis("url", "http://192.168.1.1/paypal", heuristic_res, ml_res)
    assert result.composite_risk_score >= 70
    assert result.risk_level == "DANGEROUS"
    assert len(result.recommendations) > 0


def test_fuse_text_smishing_override():
    heuristic_res = {
        "score": 70,
        "indicators": [
            {
                "name": "OTP / Security Code Harvesting",
                "severity": "CRITICAL",
                "description": "Steals OTP",
                "evidence": "send your OTP",
            }
        ],
        "details": {},
    }
    ml_res = {
        "prediction": "spam",
        "probability": 0.88,
        "spam_probability": 0.88,
        "model": "TF-IDF + Logistic Regression",
        "model_version": "1.0.0",
    }
    result = fuse_risk_analysis("text", "urgent OTP code", heuristic_res, ml_res)
    # Critical indicator floor rule ensures score >= 80
    assert result.composite_risk_score >= 80
    assert result.risk_level == "DANGEROUS"
