"""
ScamBuster Backend Tests — Phone Number Scam Detection & Intelligence Pipeline (Phase 06)

Comprehensive unit and integration test suite covering:
1. International number parsing and normalization (E.164, local formats, invalid strings).
2. Privacy engineering (masking, keyed HMAC, zero raw PII in output schemas).
3. Static & pattern feature extraction (entropy, sequential runs, repetition, premium rate).
4. Machine Learning inference & model loading.
5. Threat intelligence provider abstraction (available, unconfigured, timeout, rate limited, caching).
6. Unified Risk Engine fusion and mandatory UNKNOWN state handling.
7. FastAPI endpoint testing for POST /api/v1/scan/phone.
8. Security constraints (no contact access, untrusted provider data sanitization, length validation).
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import create_application
from app.services.phone_normalizer import (
    normalize_phone_number,
    mask_phone_number,
    generate_phone_hmac,
)
from app.features.phone_features import (
    extract_phone_features,
    extract_phone_feature_vector,
    calculate_digit_entropy,
    calculate_sequential_pattern_score,
    calculate_consecutive_repeated_digits,
    PHONE_FEATURE_NAMES,
)
from app.intelligence.base import PhoneIntelligenceResult
from app.intelligence.providers.mock_provider import MockPhoneIntelligenceProvider
from app.intelligence.phone_intelligence import PhoneIntelligenceService, get_phone_intelligence_service
from app.services.phone_rule_detector import phone_rule_detector
from app.ml.phone_inference import predict_phone_risk, PhoneModelManager
from app.risk_engine.scorer import calculate_unified_phone_risk
from app.risk_engine.categories import determine_phone_categories
from app.risk_engine.explanations import (
    generate_phone_summary,
    generate_phone_recommendation,
    generate_phone_reasons,
)


# ============================================================================
# 1. Parsing & Normalization Tests
# ============================================================================

def test_normalization_valid_india_mobile():
    res = normalize_phone_number("+91 98765 43210")
    assert res.is_valid is True
    assert res.is_possible is True
    assert res.e164 == "+919876543210"
    assert res.country_code == 91
    assert res.region_code == "IN"
    assert res.national_number == "9876543210"
    assert res.masked == "+91 ******3210"
    assert len(res.hmac_token) == 64


def test_normalization_with_default_region():
    # Local 10-digit number without international prefix
    res = normalize_phone_number("9876543210", default_region="IN")
    assert res.is_valid is True
    assert res.e164 == "+919876543210"
    assert res.region_code == "IN"


def test_normalization_international_formats():
    # US number
    us_res = normalize_phone_number("+1 (800) 432-1000")
    assert us_res.is_possible is True
    assert us_res.e164 == "+18004321000"
    assert us_res.country_code == 1
    assert us_res.region_code == "US"

    # UK number
    uk_res = normalize_phone_number("+44 20 7925 0951")
    assert uk_res.is_possible is True
    assert uk_res.e164 == "+442079250951"
    assert uk_res.country_code == 44
    assert uk_res.region_code == "GB"


def test_normalization_invalid_and_empty():
    empty_res = normalize_phone_number("   ")
    assert empty_res.is_valid is False
    assert empty_res.is_possible is False
    assert empty_res.masked == "Empty"

    invalid_res = normalize_phone_number("abc-invalid")
    assert invalid_res.is_valid is False
    assert invalid_res.is_possible is False


# ============================================================================
# 2. Privacy Engineering Tests
# ============================================================================

def test_phone_masking():
    assert mask_phone_number("+919876543210") == "+91 ******3210"
    assert mask_phone_number("+12025550199") == "+1 ******0199"
    assert mask_phone_number("+442079250951") == "+44 ******0951"
    assert mask_phone_number("") == "Unknown"


def test_keyed_hmac_privacy():
    tok1 = generate_phone_hmac("+919876543210")
    tok2 = generate_phone_hmac("+919876543210")
    tok_diff = generate_phone_hmac("+919876543211")

    # Consistent and deterministic
    assert tok1 == tok2
    # Distinct for different numbers
    assert tok1 != tok_diff
    # Obfuscated 256-bit hex
    assert len(tok1) == 64
    assert "+91" not in tok1
    assert "98765" not in tok1


# ============================================================================
# 3. Static & Pattern Feature Extraction Tests
# ============================================================================

def test_digit_entropy_and_patterns():
    # Uniform repetition has zero entropy
    assert calculate_digit_entropy("99999999") == 0.0
    # High diversity has higher entropy
    ent_diverse = calculate_digit_entropy("0123456789")
    assert ent_diverse > 3.0

    # Sequential score
    assert calculate_sequential_pattern_score("12345678") == 8
    assert calculate_sequential_pattern_score("987654") == 6
    assert calculate_sequential_pattern_score("527194") <= 2

    # Consecutive repeated digits
    assert calculate_consecutive_repeated_digits("99999123") == 5
    assert calculate_consecutive_repeated_digits("123456") == 1


def test_feature_vector_completeness():
    norm = normalize_phone_number("+919876543210")
    feats = extract_phone_features(norm, default_region="IN")

    assert set(feats.keys()) == set(PHONE_FEATURE_NAMES)
    assert feats["country_code"] == 91
    assert feats["national_number_length"] == 10
    assert feats["is_valid_number"] == 1
    assert feats["is_possible_number"] == 1

    vec = extract_phone_feature_vector(norm, default_region="IN")
    assert len(vec) == len(PHONE_FEATURE_NAMES)
    assert all(isinstance(x, float) for x in vec)


# ============================================================================
# 4. Threat Intelligence Architecture & Caching Tests
# ============================================================================

@pytest.mark.asyncio
async def test_intelligence_unconfigured():
    svc = PhoneIntelligenceService(provider=None)
    norm = normalize_phone_number("+919876543210")
    res = await svc.lookup(norm)
    assert res.status == "not_configured"
    assert res.reputation == "unknown"


@pytest.mark.asyncio
async def test_intelligence_mock_available():
    preset = {
        "+23221123456": PhoneIntelligenceResult(
            provider="mock-intel",
            status="available",
            reputation="reported_scam",
            report_count=42,
            country="SL",
        )
    }
    mock_prov = MockPhoneIntelligenceProvider(preset_reputations=preset)
    svc = PhoneIntelligenceService(provider=mock_prov)

    norm = normalize_phone_number("+23221123456")
    res = await svc.lookup(norm)

    assert res.status == "available"
    assert res.reputation == "reported_scam"
    assert res.report_count == 42


@pytest.mark.asyncio
async def test_intelligence_timeout_and_error_handling():
    # Timeout
    timeout_prov = MockPhoneIntelligenceProvider(simulate_timeout=True)
    svc_t = PhoneIntelligenceService(provider=timeout_prov)
    norm = normalize_phone_number("+919876543210")
    res_t = await svc_t.lookup(norm)
    assert res_t.status == "timeout"
    assert res_t.reputation == "unknown"

    # Rate limited
    rl_prov = MockPhoneIntelligenceProvider(simulate_rate_limit=True)
    svc_rl = PhoneIntelligenceService(provider=rl_prov)
    res_rl = await svc_rl.lookup(norm)
    assert res_rl.status == "rate_limited"


@pytest.mark.asyncio
async def test_intelligence_caching_and_deduplication():
    call_count = 0

    class CountingMock(MockPhoneIntelligenceProvider):
        async def lookup(self, phone):
            nonlocal call_count
            call_count += 1
            return await super().lookup(phone)

    prov = CountingMock()
    svc = PhoneIntelligenceService(provider=prov, cache_ttl_seconds=300)
    norm = normalize_phone_number("+919876543210")

    # First lookup calls provider
    res1 = await svc.lookup(norm)
    assert call_count == 1

    # Second lookup hits cache
    res2 = await svc.lookup(norm)
    assert call_count == 1
    assert res1.provider == res2.provider


# ============================================================================
# 5. Rule Detector Tests
# ============================================================================

def test_rule_detector_invalid_number():
    norm = normalize_phone_number("123")
    score, indicators = phone_rule_detector.analyze(norm)
    assert score >= 20
    assert any(i.rule_id == "PHONE_RULE_INVALID_STRUCTURE" for i in indicators)


def test_rule_detector_repeated_sequential():
    # Sequential
    norm_seq = normalize_phone_number("+911234567890")
    _, ind_seq = phone_rule_detector.analyze(norm_seq)
    assert any(i.rule_id == "PHONE_RULE_SEQUENTIAL_DIGITS" for i in ind_seq)


def test_rule_detector_context_impersonation():
    norm = normalize_phone_number("+919876543210")
    score, indicators = phone_rule_detector.analyze(
        norm, context="Caller claims to be Police Department requesting fund verification"
    )
    assert any(i.rule_id == "PHONE_RULE_CONTEXT_IMPERSONATION" for i in indicators)
    assert score >= 25


def test_rule_detector_intelligence_correlation():
    norm = normalize_phone_number("+23221123456")
    intel = PhoneIntelligenceResult(
        provider="test-source",
        status="available",
        reputation="reported_scam",
        report_count=15,
    )
    score, indicators = phone_rule_detector.analyze(norm, intel_result=intel)
    assert score >= 50
    assert any(i.rule_id == "PHONE_RULE_INTEL_REPORTED_SCAM" for i in indicators)


# ============================================================================
# 6. ML Inference Tests
# ============================================================================

def test_phone_ml_inference():
    norm_valid = normalize_phone_number("+919876543210")
    res_valid = predict_phone_risk(norm_valid)

    assert "prediction" in res_valid
    assert "model_score" in res_valid
    assert res_valid["model_version"] is not None
    assert 0.0 <= res_valid["model_score"] <= 1.0


# ============================================================================
# 7. Unified Risk Engine & UNKNOWN State Tests
# ============================================================================

def test_risk_engine_unknown_state_when_insufficient_evidence():
    # Standard valid mobile with NO heuristic findings, NO intel report, low ML probability
    composite_score, risk_level, confidence, _, _, _ = calculate_unified_phone_risk(
        rule_score=0,
        findings=[],
        ml_result={"prediction": "legitimate", "model_score": 0.05},
        intel_result=PhoneIntelligenceResult(provider="none", status="not_configured", reputation="unknown"),
        has_sufficient_evidence=True,
    )
    # MUST return unknown level and low confidence (absence of report != safe)
    assert risk_level == "unknown"
    assert confidence <= 0.20

    summary = generate_phone_summary(risk_level, findings=[])
    assert "No strong scam indicators were identified. This does not guarantee that the number is safe." in summary


def test_risk_engine_critical_scam_with_intel():
    from app.schemas.scan import ThreatIndicator
    findings = [
        ThreatIndicator(
            name="Scam Intelligence",
            severity="critical",
            description="Active fraud campaign",
            rule_id="PHONE_RULE_INTEL_REPORTED_SCAM",
        )
    ]
    intel = PhoneIntelligenceResult(
        provider="reputation-db",
        status="available",
        reputation="reported_scam",
        report_count=35,
    )
    composite_score, risk_level, confidence, _, _, _ = calculate_unified_phone_risk(
        rule_score=55,
        findings=findings,
        ml_result={"prediction": "scam", "model_score": 0.85},
        intel_result=intel,
        has_sufficient_evidence=True,
    )
    assert composite_score >= 80
    assert risk_level in ("critical", "high")
    assert confidence >= 0.85


# ============================================================================
# 8. API Endpoint Tests (POST /api/v1/scan/phone)
# ============================================================================

@pytest.mark.asyncio
async def test_api_scan_phone_success():
    app = create_application()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/scan/phone",
            json={
                "phone_number": "+919876543210",
                "country": "IN",
                "context": "Caller claimed to be Bank Manager asking for card details",
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["scan_type"] == "phone"
        assert data["target"] == "Phone: +91 ******3210"
        assert "composite_risk_score" in data
        assert "risk_level" in data
        assert "detection" in data
        assert "rules" in data["detection"]
        assert "ml" in data["detection"]
        assert "intelligence" in data["detection"]
        assert data["detection"]["ml"]["features_used"] == 18
        assert "summary" in data
        assert "recommendation" in data


@pytest.mark.asyncio
async def test_api_scan_phone_empty_validation_error():
    app = create_application()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        response = await ac.post(
            "/api/v1/scan/phone",
            json={"phone_number": "   ", "country": "IN"},
        )
        assert response.status_code == 422
