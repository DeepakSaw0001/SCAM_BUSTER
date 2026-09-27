"""
Unit & Integration Tests for ScamBuster URL Machine Learning Pipeline (Phase 03)

Validates:
1. Feature consistency between training and inference schema.
2. Safe model loading and artifact metadata.
3. Known prediction test fixtures (benign vs malicious URLs).
4. API endpoint POST /api/v1/scan/url returns ML detection and rule breakdown.
5. Error handling: invalid URLs, corrupt/missing model fallback (fails safely).
"""

import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app
from app.services.url_feature_extractor import (
    URL_FEATURE_NAMES,
    extract_url_features,
    extract_feature_dict,
)
from app.ml.preprocessing import (
    format_features_as_dataframe,
    preprocess_url_for_inference,
)
from app.ml.inference import (
    UrlModelManager,
    predict_url_threat,
)


# --- 1. Feature Consistency Tests ---

def test_feature_consistency_schema():
    """Verify that training feature schema exactly matches inference feature schema."""
    assert len(URL_FEATURE_NAMES) == 23

    # Expected feature list defined in Phase 03 documentation
    expected_features = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "fragment_length",
        "number_of_dots",
        "number_of_hyphens",
        "number_of_digits",
        "number_of_special_characters",
        "number_of_slashes",
        "number_of_question_marks",
        "number_of_equals",
        "subdomain_count",
        "path_depth",
        "query_parameter_count",
        "has_ip_hostname",
        "has_port",
        "uses_https",
        "suspicious_keyword_count",
        "has_at_symbol",
        "has_double_slash_redirect",
        "digit_ratio",
        "entropy",
    ]
    assert URL_FEATURE_NAMES == expected_features

    # Test feature extraction on sample URL
    test_url = "https://legitimate-bank.com/portal/login?id=452"
    f_dict = extract_feature_dict(test_url)
    assert set(f_dict.keys()) == set(URL_FEATURE_NAMES)

    df = format_features_as_dataframe(f_dict)
    assert list(df.columns) == URL_FEATURE_NAMES
    assert len(df) == 1
    assert df["has_ip_hostname"].iloc[0] == 0
    assert df["uses_https"].iloc[0] == 1


# --- 2. Model Loading Tests ---

def test_model_loading_and_metadata():
    """Verify that the model manager loads the trained artifact and metadata correctly."""
    manager = UrlModelManager.get_instance()
    assert manager.is_ready() is True
    assert manager.model is not None
    assert manager.model_version == "url-model-1.0"
    assert len(manager.top_important_features) > 0


# --- 3. Known Prediction Fixtures ---

def test_prediction_known_benign_urls():
    """Verify ML predictions on standard benign domains."""
    benign_fixtures = [
        "https://google.com",
        "https://github.com",
        "https://python.org",
        "https://stackoverflow.com",
    ]
    for url in benign_fixtures:
        res = predict_url_threat(url)
        assert res["available"] is True
        assert res["prediction"] == "benign"
        assert res["model_probability"] < 0.50
        assert res["model_version"] == "url-model-1.0"
        assert res["features_used"] == 23


def test_prediction_known_malicious_urls():
    """Verify ML predictions on hostile/phishing URL patterns."""
    malicious_fixtures = [
        "http://192.168.1.100:8080/account/login/verify.php?token=xyz",
        "http://secure-login.paypal-verification.alert-update.com/login.html",
        "http://free-prize-winner-claim.xyz/update/password?user=victim",
    ]
    for url in malicious_fixtures:
        res = predict_url_threat(url)
        assert res["available"] is True
        assert res["prediction"] == "malicious"
        assert res["model_probability"] > 0.50
        assert res["model_version"] == "url-model-1.0"
        assert len(res["top_contributing_features"]) > 0


# --- 4. API Endpoint Integration ---

@pytest.mark.asyncio
async def test_api_scan_url_returns_ml_and_rule_detection():
    """Verify that POST /api/v1/scan/url returns full dual-detection structure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Scan a phishing URL
        phish_url = "http://192.168.1.50:8080/secure/bank/login.php?verify=1"
        response = await client.post("/api/v1/scan/url", json={"url": phish_url})
        assert response.status_code == 200
        data = response.json()

        # Check top-level contract
        assert data["scan_type"] == "url"
        assert data["input_type"] == "url"
        assert data["status"] == "completed"
        assert data["composite_risk_score"] >= 70
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert "confidence" in data

        # Check Detection Sources (Rules + ML)
        assert "detection" in data
        assert "rules" in data["detection"]
        assert "ml" in data["detection"]

        rules_info = data["detection"]["rules"]
        assert rules_info["risk_score"] > 0
        assert len(rules_info["indicators"]) > 0

        ml_info = data["detection"]["ml"]
        assert ml_info["prediction"] == "malicious"
        assert ml_info["model_score"] > 0.50
        assert ml_info["model_version"] == "url-model-1.0"
        assert ml_info["features_used"] == 23

        # Check explainability reasons delineate rules and ML
        assert any("Rule Evidence:" in r for r in data["reasons"])
        assert any("ML Evidence:" in r for r in data["reasons"])


@pytest.mark.asyncio
async def test_api_scan_url_benign():
    """Verify scan on a clean legitimate URL."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan/url", json={"url": "https://python.org"})
        assert response.status_code == 200
        data = response.json()

        assert data["risk_level"] in ("VERY_LOW", "LOW")
        assert data["composite_risk_score"] < 40
        assert data["detection"]["ml"]["prediction"] == "benign"


# --- 5. Error Handling & Safety ---

@pytest.mark.asyncio
async def test_api_scan_invalid_url_fails_safely():
    """Verify API returns 422 for malformed URL."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan/url", json={"url": "not_a_valid_url"})
        assert response.status_code == 422


def test_inference_graceful_fallback_when_corrupted():
    """Verify inference handles corrupted/missing inputs without crashing."""
    manager = UrlModelManager()
    # Temporarily set model to None to test offline fallback
    orig_model = manager.model
    manager.model = None

    fallback_res = manager.predict("https://google.com")
    assert fallback_res["available"] is False
    assert fallback_res["prediction"] == "unknown"
    assert fallback_res["model_score"] == 0.0

    # Restore model
    manager.model = orig_model
