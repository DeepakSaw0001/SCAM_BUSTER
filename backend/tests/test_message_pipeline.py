"""
ScamBuster Phase 04 — SMS / Message Scam Detection Test Suite

Covers:
1. Input Validation (empty, pure whitespace, boundary lengths, unicode spoofing)
2. Preprocessing & Entity Extraction (NFKC normalization, whitespace, URLs, phones, emails, token cleaning)
3. Feature Engineering (statistical, structural, semantic keyword counters)
4. Deterministic Rule Detector (credential solicitation, urgency, threat coercion, rewards, links, uppercase)
5. NLP ML Inference Service (model loading, prediction probabilities, safe offline fallbacks)
6. Unified Risk Engine Integration (fusion weights, defense-in-depth guardrails, categories, explainability)
7. End-to-End API Integration (POST /api/v1/scan/message)
8. Privacy & Data Minimization (no raw SMS in target, metadata-only storage)
9. Insufficient Evidence / UNKNOWN Handling
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.services.message_preprocessor import preprocess_message
from app.services.message_feature_extractor import extract_message_features, ALL_MESSAGE_FEATURES
from app.services.message_rule_detector import evaluate_message_rules
from app.ml.message_inference import get_message_model_manager, predict_message_threat
from app.risk_engine.scorer import (
    calculate_message_rule_score,
    calculate_unified_message_risk,
)
from app.risk_engine.categories import (
    determine_message_categories,
    CATEGORY_POTENTIAL_SCAM,
    CATEGORY_CREDENTIAL_THEFT,
    CATEGORY_SMISHING_LURE,
    CATEGORY_BENIGN_BASELINE,
)
from app.risk_engine.explanations import (
    generate_message_summary,
    generate_message_recommendation,
    generate_message_reasons,
)
from app.schemas.scan import MessageScanRequest


# ==============================================================================
# 1. INPUT VALIDATION TESTS
# ==============================================================================

def test_validation_empty_and_whitespace():
    """Verify empty or whitespace-only messages are rejected by schema validator."""
    with pytest.raises(ValueError):
        MessageScanRequest(message="")

    with pytest.raises(ValueError):
        MessageScanRequest(message="    \t\n  ")


def test_validation_valid_message():
    """Verify valid messages are accepted and preserved."""
    req = MessageScanRequest(message="Hello, this is a test message.")
    assert req.message == "Hello, this is a test message."


def test_validation_alias_text_field():
    """Verify backward-compatible alias 'text' is properly mapped to 'message'."""
    req = MessageScanRequest.model_validate({"text": "Your OTP code is 987654."})
    assert req.message == "Your OTP code is 987654."


# ==============================================================================
# 2. PREPROCESSING & ENTITY EXTRACTION TESTS
# ==============================================================================

def test_preprocessing_unicode_and_whitespace():
    """Verify Unicode NFKC normalization and whitespace collapsing."""
    # Full-width characters and messy spacing
    raw = "ＵＲＧＥＮＴ:   Please   verify    account!"
    prep = preprocess_message(raw)
    assert prep.normalized_text == "URGENT: Please verify account!"
    assert prep.char_count == len(raw.strip())
    assert prep.word_count == 4


def test_preprocessing_entity_extraction():
    """Verify safe regex extraction of embedded URLs, phone numbers, and emails."""
    text = (
        "Call us at +1-800-555-0199 or email fraud-alert@bank.com. "
        "Visit https://chase-security-verify.xyz/login immediately."
    )
    prep = preprocess_message(text)
    assert "https://chase-security-verify.xyz/login" in prep.extracted_urls
    assert "fraud-alert@bank.com" in prep.extracted_emails
    assert len(prep.extracted_phone_numbers) >= 1
    # Check that cleaned_text strips entities for pure text modeling
    assert "https" not in prep.cleaned_text
    assert "fraud-alert" not in prep.cleaned_text


# ==============================================================================
# 3. FEATURE EXTRACTION TESTS
# ==============================================================================

def test_message_feature_extractor():
    """Verify statistical, structural, and semantic feature calculations."""
    text = "CONGRATULATIONS! You won $10,000 lottery cash prize! Visit https://win.xyz now!"
    features = extract_message_features(text)

    assert features.message_length == len(text)
    assert features.uppercase_ratio > 0.20
    assert features.exclamation_count >= 2
    assert features.has_url is True
    assert features.url_count == 1
    assert features.reward_terms_count >= 2  # congratulations, won, prize, etc.
    assert features.call_to_action_count >= 1  # visit


# ==============================================================================
# 4. DETERMINISTIC RULE DETECTOR TESTS
# ==============================================================================

def test_rule_credential_solicitation():
    """Verify critical credential/OTP rule triggers."""
    text = "URGENT: Reply with your one-time password (OTP) and bank password now."
    prep = preprocess_message(text)
    features = extract_message_features(text, prep)
    findings = evaluate_message_rules(prep, features)

    rule_ids = {f.rule_id for f in findings}
    assert "RULE_CREDENTIAL_SOLICITATION" in rule_ids
    severities = {f.severity for f in findings}
    assert "CRITICAL" in severities


def test_rule_urgency_and_threat():
    """Verify urgency and threat coercion rules trigger."""
    text = "Your account has been suspended due to unauthorized access. Act immediately."
    prep = preprocess_message(text)
    features = extract_message_features(text, prep)
    findings = evaluate_message_rules(prep, features)

    rule_ids = {f.rule_id for f in findings}
    assert "RULE_URGENCY_PRESSURE" in rule_ids
    assert "RULE_THREAT_COERCION" in rule_ids


def test_rule_clean_message():
    """Verify benign everyday messages trigger zero malicious rules."""
    text = "Hey are we still meeting up for dinner tonight around 7pm?"
    prep = preprocess_message(text)
    features = extract_message_features(text, prep)
    findings = evaluate_message_rules(prep, features)
    assert len(findings) == 0


# ==============================================================================
# 5. NLP ML INFERENCE SERVICE TESTS
# ==============================================================================

def test_ml_inference_ready():
    """Verify singleton model manager loads the trained artifact."""
    mgr = get_message_model_manager()
    assert mgr.is_ready() is True
    assert mgr.model_version == "message-model-1.0"


def test_ml_inference_predictions():
    """Verify inference outputs probability and predicted class."""
    scam_msg = "WINNER! You have won a 1000 Walmart Gift Card. Call now to claim prize."
    res_scam = predict_message_threat(scam_msg)
    assert res_scam["available"] is True
    assert res_scam["prediction"] == "scam"
    assert res_scam["model_probability"] > 0.50

    ham_msg = "Hey mom, I will be home by 6 for dinner."
    res_ham = predict_message_threat(ham_msg)
    assert res_ham["available"] is True
    assert res_ham["prediction"] == "legitimate"
    assert res_ham["model_probability"] < 0.50


# ==============================================================================
# 6. UNIFIED RISK ENGINE TESTS
# ==============================================================================

def test_unified_risk_engine_scoring():
    """Verify score combination, defense-in-depth guardrails, and categories."""
    # Critical OTP solicitation rule
    text = "Please send your banking OTP code immediately to avoid suspension."
    prep = preprocess_message(text)
    features = extract_message_features(text, prep)
    findings = evaluate_message_rules(prep, features)
    ml_res = predict_message_threat(text, prep)

    score, level, conf, r_score, m_score = calculate_unified_message_risk(findings, ml_res)
    assert score >= 75
    assert level in ("high", "critical")
    assert conf >= 0.80

    cats = determine_message_categories(findings, ml_result=ml_res)
    assert CATEGORY_CREDENTIAL_THEFT in cats or CATEGORY_POTENTIAL_SCAM in cats


def test_unified_risk_insufficient_evidence():
    """Verify unknown status when evidence is insufficient."""
    score, level, conf, r_score, m_score = calculate_unified_message_risk(
        [], None, has_sufficient_evidence=False
    )
    assert score == 0
    assert level == "unknown"
    assert conf == 0.0


# ==============================================================================
# 7. END-TO-END API INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_scan_message_api_scam():
    """Test POST /api/v1/scan/message with smishing lure."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "message": "URGENT: Your Chase account is locked. Verify at http://192.168.1.1/login or reply with your OTP.",
            "sender": "+14155550199"
        }
        res = await client.post("/api/v1/scan/message", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "completed"
    assert data["scan_type"] == "message"
    assert data["composite_risk_score"] >= 70
    assert data["risk_level"] in ("HIGH", "CRITICAL")
    assert "detection" in data
    assert "rules" in data["detection"]
    assert "ml" in data["detection"]
    assert data["detection"]["ml"]["model_version"] == "message-model-1.0"
    # Embedded URLs must be analyzed statically without outbound requests
    assert data["detection"]["embedded_urls"] is not None
    assert len(data["detection"]["embedded_urls"]) >= 1

    # Privacy verification: Raw OTP / sensitive message text must NOT be stored as target
    assert "URGENT: Your Chase" not in data["target"]
    assert "SMS" in data["target"]


@pytest.mark.asyncio
async def test_scan_message_api_benign():
    """Test POST /api/v1/scan/message with benign personal chat."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "message": "Hey Alex, are we still studying together at the campus library at 3pm?",
        }
        res = await client.post("/api/v1/scan/message", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["composite_risk_score"] <= 20
    assert data["risk_level"] in ("LOW", "VERY_LOW")
    assert data["detection"]["ml"]["prediction"] == "legitimate"


@pytest.mark.asyncio
async def test_scan_message_api_validation_error():
    """Test POST /api/v1/scan/message rejects empty input."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.post("/api/v1/scan/message", json={"message": "   "})

    assert res.status_code == 422
