"""Test suite for Android Permission and Privacy Risk Analysis (Phase 08).

Validates:
- Centralized permission catalog (known, unknown, deprecated, runtime vs install)
- Android API level version awareness (storage evolution, notification permissions, background location)
- Multi-permission capability combinations (surveillance, communication, overlay/accessibility)
- Contextual category alignment (expected vs unusual vs unknown)
- Bytecode / DEX API correlation (correlated, permission-only, API-only)
- Privacy feature extraction and ML model inference
- Unified Risk Engine integration without double-counting
- Security edge cases (large permission sets, malformed inputs, unknown permissions)
"""

import pytest
from app.security.android_permissions.catalog import (
    PERMISSION_CATALOG,
    get_permission_metadata,
    is_high_impact_permission,
)
from app.security.android_permissions.categories import (
    CAT_CAMERA,
    CAT_MICROPHONE,
    CAT_SMS,
    CAT_UNKNOWN,
    CAT_LOCATION,
    SENSITIVITY_HIGH,
    SENSITIVITY_VERY_HIGH,
    SENSITIVITY_LOW,
)
from app.security.android_permissions.version import (
    get_storage_permission_model,
    is_notification_runtime_required,
    is_runtime_permission_at_target,
    parse_sdk_version,
)
from app.security.android_permissions.api_mapping import (
    correlate_permissions_with_apis,
    find_apis_in_dex_content,
)
from app.security.android_permissions.risk_rules import (
    evaluate_permission_combinations,
    evaluate_context_mismatch,
    CAT_CALCULATOR,
    CAT_CAMERA as APP_CAT_CAMERA,
)
from app.services.apk_privacy_rule_detector import (
    ApkPrivacyRuleDetector,
    analyze_apk_privacy,
)
from app.ml.apk_privacy_inference import predict_apk_privacy
from app.features.apk_privacy_features import extract_privacy_features
from app.risk_engine.scorer import calculate_unified_apk_risk


class TestAndroidPermissionCatalog:
    """Tests for centralized Android permission taxonomy and catalog."""

    def test_known_sensitive_permissions(self):
        camera_meta = get_permission_metadata("android.permission.CAMERA")
        assert camera_meta.category == CAT_CAMERA
        assert camera_meta.sensitivity == SENSITIVITY_HIGH
        assert camera_meta.runtime_permission is True
        assert "image_capture" in camera_meta.privacy_impact
        assert "visual" in camera_meta.why_it_matters.lower() or "photos" in camera_meta.description.lower()

        audio_meta = get_permission_metadata("android.permission.RECORD_AUDIO")
        assert audio_meta.category == CAT_MICROPHONE
        assert audio_meta.sensitivity == SENSITIVITY_HIGH
        assert audio_meta.runtime_permission is True

        sms_meta = get_permission_metadata("android.permission.READ_SMS")
        assert sms_meta.category == CAT_SMS
        assert sms_meta.sensitivity == SENSITIVITY_VERY_HIGH

    def test_unknown_permission_handling(self):
        unknown_perm = "com.custom.vendor.SECRET_ACTION"
        assert unknown_perm not in PERMISSION_CATALOG
        meta = get_permission_metadata(unknown_perm)
        assert meta.category == CAT_UNKNOWN
        assert meta.sensitivity == SENSITIVITY_LOW
        assert "not recognized" in meta.description.lower()

    def test_deprecated_storage_permission(self):
        storage_meta = get_permission_metadata("android.permission.READ_EXTERNAL_STORAGE")
        assert storage_meta.deprecated_api_level == 33
        assert "storage" in storage_meta.why_it_matters.lower()

    def test_high_impact_identification(self):
        assert is_high_impact_permission("android.permission.BIND_ACCESSIBILITY_SERVICE")
        assert is_high_impact_permission("android.permission.SYSTEM_ALERT_WINDOW")
        assert not is_high_impact_permission("android.permission.INTERNET")


class TestAndroidVersionAwareness:
    """Tests for Android version semantics across API levels."""

    def test_storage_semantics_evolution(self):
        legacy = get_storage_permission_model(28)
        assert "Legacy External Storage" in legacy["model"]

        scoped = get_storage_permission_model(30)
        assert "Scoped Storage" in scoped["model"]

        modern = get_storage_permission_model(34)
        assert "Granular Media" in modern["model"]

    def test_notification_permission_requirement(self):
        assert not is_notification_runtime_required(31)
        assert is_notification_runtime_required(33)
        assert is_notification_runtime_required(35)

    def test_runtime_permission_at_target(self):
        assert not is_runtime_permission_at_target("android.permission.CAMERA", 21, is_dangerous=True)
        assert is_runtime_permission_at_target("android.permission.CAMERA", 30, is_dangerous=True)
        assert not is_runtime_permission_at_target("android.permission.INTERNET", 34, is_dangerous=False)


class TestPermissionCombinations:
    """Tests for multi-permission capability combination analysis."""

    def test_surveillance_combination(self):
        perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.ACCESS_FINE_LOCATION",
        ]
        combos = evaluate_permission_combinations(perms)
        names = [c.name for c in combos]
        assert "Broad Physical Sensor Access" in names

    def test_communication_exfiltration_combination(self):
        perms = [
            "android.permission.READ_CONTACTS",
            "android.permission.READ_SMS",
            "android.permission.READ_PHONE_STATE",
        ]
        combos = evaluate_permission_combinations(perms)
        names = [c.name for c in combos]
        assert "Comprehensive Communication Access" in names

    def test_accessibility_overlay_combination(self):
        perms = [
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
        ]
        combos = evaluate_permission_combinations(perms)
        names = [c.name for c in combos]
        assert "Full UI Observation and Overlay Capability" in names

    def test_empty_or_benign_permissions_no_combos(self):
        perms = ["android.permission.INTERNET", "android.permission.VIBRATE"]
        combos = evaluate_permission_combinations(perms)
        assert len(combos) == 0


class TestContextMismatchAnalysis:
    """Tests for contextual application category alignment."""

    def test_expected_camera_application(self):
        perms = [
            "android.permission.CAMERA",
            "android.permission.RECORD_AUDIO",
            "android.permission.READ_MEDIA_IMAGES",
            "android.permission.INTERNET",
        ]
        result = evaluate_context_mismatch(category="camera", permissions=perms)
        assert result.mismatch_level == "LOW"
        assert result.context_status == "established"
        assert result.mismatch_score == 0

    def test_suspicious_calculator_application(self):
        perms = [
            "android.permission.READ_SMS",
            "android.permission.READ_CONTACTS",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
        ]
        result = evaluate_context_mismatch(category="calculator", permissions=perms)
        assert result.mismatch_level == "HIGH"
        assert result.mismatch_score > 0
        assert len(result.unexpected_permissions) >= 3
        assert "unexpected" in result.explanation.lower()

    def test_unknown_application_context_no_penalty(self):
        perms = [
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
        ]
        result = evaluate_context_mismatch(category="unknown", permissions=perms)
        assert result.context_status == "unknown"
        assert result.mismatch_level == "NONE"
        assert result.mismatch_score == 0
        assert "could not be established" in result.explanation


class TestBytecodeApiCorrelation:
    """Tests for correlating permissions against static DEX/Dalvik API signatures."""

    def test_correlated_audio_api(self):
        perms = ["android.permission.RECORD_AUDIO"]
        dex_bytes = b"header...android/media/AudioRecord...setAudioSource...trailer"
        correlations, count = correlate_permissions_with_apis(perms, dex_data=dex_bytes)
        audio_cors = [c for c in correlations if c.permission == "android.permission.RECORD_AUDIO"]
        assert len(audio_cors) == 1
        assert audio_cors[0].status == "CORRELATED"
        assert audio_cors[0].confidence == "HIGH"
        assert count >= 1

    def test_permission_only_when_no_api_present(self):
        perms = ["android.permission.RECORD_AUDIO"]
        dex_bytes = b"header...simple text...no media calls...trailer"
        correlations, count = correlate_permissions_with_apis(perms, dex_data=dex_bytes)
        audio_cors = [c for c in correlations if c.permission == "android.permission.RECORD_AUDIO"]
        assert len(audio_cors) == 1
        assert audio_cors[0].status == "PERMISSION_ONLY"
        assert audio_cors[0].confidence == "MEDIUM"

    def test_api_only_signature(self):
        perms = ["android.permission.INTERNET"]
        dex_bytes = b"header...android/hardware/Camera...takePicture...trailer"
        correlations, count = correlate_permissions_with_apis(perms, dex_data=dex_bytes)
        camera_cors = [c for c in correlations if c.permission == "android.permission.CAMERA"]
        assert len(camera_cors) == 1
        assert camera_cors[0].status == "API_ONLY"


class TestApkPrivacyRuleDetector:
    """Tests for complete ApkPrivacyRuleDetector execution."""

    def test_benign_minimal_app(self):
        detector = ApkPrivacyRuleDetector()
        res = detector.analyze(
            declared_permissions=["android.permission.INTERNET"],
            category="utility",
        )
        assert res.privacy_score < 25
        assert res.privacy_risk_level in ["very_low", "low"]
        assert res.high_impact_count == 0
        assert "static" in res.limitation_disclaimer.lower() and "runtime" in res.limitation_disclaimer.lower()

    def test_high_privacy_risk_app(self):
        detector = ApkPrivacyRuleDetector()
        dex_bytes = b"android/accessibilityservice/AccessibilityService...android/telephony/SmsManager"
        res = detector.analyze(
            declared_permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_SMS",
                "android.permission.RECEIVE_SMS",
                "android.permission.READ_CONTACTS",
                "android.permission.ACCESS_BACKGROUND_LOCATION",
            ],
            dex_data=dex_bytes,
            category="calculator",
            exported_component_count=3,
        )
        assert res.privacy_score >= 60
        assert res.privacy_risk_level in ["high", "critical"]
        assert any("ACCESSIBILITY" in cap.upper() for cap in res.high_impact_capabilities)
        assert any("SMS" in cap.upper() for cap in res.high_impact_capabilities)
        assert res.context_analysis["mismatch_level"] == "HIGH"
        assert len(res.api_correlations) >= 1

    def test_no_runtime_claims_in_indicators(self):
        detector = ApkPrivacyRuleDetector()
        dex_bytes = b"android/media/AudioRecord"
        res = detector.analyze(
            declared_permissions=["android.permission.RECORD_AUDIO"],
            dex_data=dex_bytes,
            category="utility",
        )
        for ind in res.indicators:
            desc = ind.description.lower()
            assert "app recorded" not in desc
            assert "stole" not in desc
            assert "accessed your" not in desc


class TestMlPrivacyPipeline:
    """Tests for ML feature extraction and model inference."""

    def test_feature_extraction(self):
        detector = ApkPrivacyRuleDetector()
        privacy_res = detector.analyze(
            declared_permissions=[
                "android.permission.CAMERA",
                "android.permission.RECORD_AUDIO",
                "android.permission.READ_SMS",
            ],
            category="utility",
        )
        features = extract_privacy_features(privacy_res)
        assert features["permission_count"] == 3
        assert features["sensitive_permission_count"] == 3
        assert features["has_sms_capability"] == 1
        assert len(features) == 16

    def test_ml_inference_service(self):
        detector = ApkPrivacyRuleDetector()
        privacy_res = detector.analyze(
            declared_permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
            ],
            category="game",
        )
        pred = predict_apk_privacy(privacy_res)
        assert pred is not None
        assert pred["available"] is True
        assert pred["prediction"] in ["low", "medium", "high", "critical"]
        assert 0.0 <= pred["model_probability"] <= 1.0


class TestUnifiedRiskEngineIntegration:
    """Tests for passing privacy evidence into calculate_unified_apk_risk."""

    def test_clean_app_retains_low_malware_score(self):
        privacy_res = analyze_apk_privacy(
            declared_permissions=["android.permission.INTERNET"],
            category="utility",
        )
        score, level, conf, r_score, m_score, i_score = calculate_unified_apk_risk(
            rule_score=0,
            findings=[],
            ml_result={"prediction": "clean", "model_score": 0.05},
            intel_result=None,
            privacy_result=privacy_res,
        )
        assert level in ["very_low", "low"]
        assert score < 40

    def test_high_privacy_risk_elevates_scrutiny_floor(self):
        privacy_res = analyze_apk_privacy(
            declared_permissions=[
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.READ_SMS",
                "android.permission.READ_CONTACTS",
            ],
            category="calculator",
        )
        score, level, conf, r_score, m_score, i_score = calculate_unified_apk_risk(
            rule_score=10,
            findings=[],
            ml_result={"prediction": "clean", "model_score": 0.10},
            intel_result=None,
            privacy_result=privacy_res,
        )
        assert score >= 45


class TestSecurityAndEdgeCases:
    """Security tests against malformed, excessive, or malicious payloads."""

    def test_extremely_large_permission_list(self):
        huge_perm_list = [f"android.permission.CUSTOM_PERM_{i}" for i in range(1000)]
        detector = ApkPrivacyRuleDetector()
        res = detector.analyze(declared_permissions=huge_perm_list)
        assert res.total_requested_count == 1000

    def test_malformed_permission_strings(self):
        malformed = ["", "...", "///invalid", "android.permission."]
        detector = ApkPrivacyRuleDetector()
        res = detector.analyze(declared_permissions=malformed)
        assert res.total_requested_count >= 0

    def test_null_and_special_char_categories(self):
        detector = ApkPrivacyRuleDetector()
        res = detector.analyze(
            declared_permissions=["android.permission.CAMERA"],
            category="<script>alert(1)</script>",
        )
        assert res.context_analysis["context_status"] == "unknown"
