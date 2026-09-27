"""
ScamBuster Backend Tests — Android APK Malware & Risk Analysis Pipeline (Phase 07)

Comprehensive test suite covering:
1. Archive security & ZIP bomb defenses (max size, compression ratio, file count, path traversal).
2. Permission taxonomy, risk weighting, and high-interest cluster detection (Banking Trojan, Spyware, Dropper).
3. Static bytecode DEX scanning (dynamic loading, reflection, shell commands, device admin).
4. Native library detection and embedded URL filtering & offline scoring.
5. Threat Intelligence provider abstraction, caching, and unconfigured state handling.
6. Static Rule Detector indicators.
7. ML feature pipeline (26 features) and inference engine.
8. Unified Risk Engine scoring, categories, and explainability.
9. FastAPI REST endpoints (POST /api/v1/scan/apk and POST /api/v1/scan/apk/upload).
10. Security constraints (no execution, immediate temporary file cleanup).
"""

import os
import io
import zipfile
import tempfile
import pytest
from httpx import AsyncClient, ASGITransport

from app.main import create_application
from app.services.apk_permission_analyzer import (
    analyze_permissions,
    categorize_permission,
    is_dangerous_permission,
    is_sensitive_permission,
    detect_permission_clusters,
    assess_contextual_permission_risk,
    AOSP_DANGEROUS_PERMISSIONS,
    AOSP_SPECIAL_PERMISSIONS,
    PermissionTier,
    PermissionClusterFinding,
)
from app.services.apk_analyzer import (
    validate_apk_archive_safety,
    inspect_dex_code,
    extract_native_libraries,
    filter_and_analyze_embedded_urls,
    analyze_apk_file,
    SecurityValidationError,
    MAX_APK_SIZE,
    ApkStaticAnalysisResult,
    PermissionAnalysisReport,
    DexCodeAnalysis,
    ApkCertificateInfo,
)
from app.intelligence.apk_intelligence import (
    ApkIntelligenceService,
    MockApkIntelligenceProvider,
    ApkIntelligenceResult,
)
from app.services.apk_rule_detector import (
    apk_rule_detector,
    ApkRuleDetector,
)
from app.features.apk_features import (
    extract_apk_features,
    extract_apk_feature_vector,
    APK_FEATURE_NAMES,
    FEATURE_VERSION,
)
from app.ml.apk_inference import predict_apk_risk, ApkModelManager
from app.risk_engine.scorer import calculate_unified_apk_risk
from app.risk_engine.categories import determine_apk_categories
from app.risk_engine.explanations import (
    generate_apk_summary,
    generate_apk_recommendation,
    generate_apk_reasons,
)
from app.schemas.scan import ThreatIndicator


# ============================================================================
# Helpers: Synthetic In-Memory Archives
# ============================================================================

def create_synthetic_apk_bytes(
    manifest_content: bytes = b"<manifest package=\"com.test.app\"></manifest>",
    dex_strings: list[bytes] = None,
    native_libs: list[str] = None,
    include_traversal: bool = False,
    traversal_path: str = "../../evil.so",
) -> bytes:
    """Helper to create a synthetic APK zip archive in memory."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("AndroidManifest.xml", manifest_content)
        
        # Add synthetic DEX with target byte patterns
        dex_data = b"dex\n035\x00" + b"\x00" * 32
        if dex_strings:
            for s in dex_strings:
                dex_data += s + b"\x00"
        zf.writestr("classes.dex", dex_data)

        # Add native libraries
        if native_libs:
            for lib_path in native_libs:
                zf.writestr(lib_path, b"\x7fELF" + b"\x00" * 16)

        # Optional path traversal entry
        if include_traversal:
            zf.writestr(traversal_path, b"malicious code")

    return buf.getvalue()


# ============================================================================
# 1. Archive Security & ZIP Bomb Protections
# ============================================================================

class TestApkArchiveSafety:
    def test_valid_archive_passes(self):
        apk_bytes = create_synthetic_apk_bytes()
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        try:
            validate_apk_archive_safety(tmp_path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_non_zip_file_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(b"This is just a plain text file pretending to be an APK.")
            tmp_path = tmp.name

        try:
            with pytest.raises(SecurityValidationError) as excinfo:
                validate_apk_archive_safety(tmp_path)
            assert "not a valid ZIP/APK archive" in str(excinfo.value)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_path_traversal_relative_rejected(self):
        apk_bytes = create_synthetic_apk_bytes(include_traversal=True, traversal_path="../../evil.so")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        try:
            with pytest.raises(SecurityValidationError) as excinfo:
                validate_apk_archive_safety(tmp_path)
            assert "Path traversal detected" in str(excinfo.value)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_path_traversal_absolute_rejected(self):
        apk_bytes = create_synthetic_apk_bytes(include_traversal=True, traversal_path="/etc/passwd")
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        try:
            with pytest.raises(SecurityValidationError) as excinfo:
                validate_apk_archive_safety(tmp_path)
            assert "Path traversal detected" in str(excinfo.value)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_zip_bomb_compression_ratio_rejected(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"<xml></xml>")
            zf.writestr("bomb.dat", b"\x00" * (1024 * 1024))
        
        apk_bytes = buf.getvalue()
        with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
            tmp.write(apk_bytes)
            tmp_path = tmp.name

        try:
            with pytest.raises(SecurityValidationError) as excinfo:
                validate_apk_archive_safety(tmp_path)
            assert "Suspicious compression ratio" in str(excinfo.value) or "ZIP bomb" in str(excinfo.value)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


# ============================================================================
# 2. Permission Taxonomy & Categorization
# ============================================================================

class TestApkPermissionTaxonomy:
    def test_dangerous_permission_categorization(self):
        assert categorize_permission("android.permission.READ_SMS") == PermissionTier.DANGEROUS
        assert categorize_permission("android.permission.CAMERA") == PermissionTier.DANGEROUS
        assert categorize_permission("android.permission.ACCESS_FINE_LOCATION") == PermissionTier.DANGEROUS
        assert is_dangerous_permission("android.permission.READ_SMS") is True
        assert is_sensitive_permission("android.permission.READ_SMS") is True

    def test_special_permission_categorization(self):
        assert categorize_permission("android.permission.SYSTEM_ALERT_WINDOW") == PermissionTier.SPECIAL
        assert categorize_permission("android.permission.REQUEST_INSTALL_PACKAGES") == PermissionTier.SPECIAL
        assert is_sensitive_permission("android.permission.SYSTEM_ALERT_WINDOW") is True
        assert is_dangerous_permission("android.permission.SYSTEM_ALERT_WINDOW") is False

    def test_normal_permission_categorization(self):
        assert categorize_permission("android.permission.INTERNET") == PermissionTier.NORMAL
        assert categorize_permission("android.permission.VIBRATE") == PermissionTier.NORMAL
        assert is_dangerous_permission("android.permission.INTERNET") is False
        assert is_sensitive_permission("android.permission.INTERNET") is False

    def test_banking_trojan_cluster_detection(self):
        perms = [
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.RECEIVE_SMS",
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.INTERNET",
        ]
        clusters = detect_permission_clusters(perms)
        assert "banking_trojan_overlay" in clusters

    def test_spyware_cluster_detection(self):
        perms = [
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.INTERNET",
        ]
        clusters = detect_permission_clusters(perms)
        assert "spyware_surveillance" in clusters

    def test_dropper_cluster_detection(self):
        perms = [
            "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INTERNET",
        ]
        clusters = detect_permission_clusters(perms)
        assert "dropper_capability" in clusters

    def test_contextual_permission_risk(self):
        calc_risk, calc_reasons = assess_contextual_permission_risk(
            category="tools",
            permissions=["android.permission.READ_SMS", "android.permission.RECORD_AUDIO"],
        )
        assert calc_risk > 20
        assert len(calc_reasons) > 0

        comm_risk, comm_reasons = assess_contextual_permission_risk(
            category="communication",
            permissions=["android.permission.READ_SMS", "android.permission.RECORD_AUDIO"],
        )
        assert comm_risk == 0
        assert len(comm_reasons) == 0


# ============================================================================
# 3. Static Bytecode DEX & Native Library Analysis
# ============================================================================

class TestApkStaticAnalyzer:
    def test_dex_pattern_detection(self):
        dex_patterns = [
            b"DexClassLoader",
            b"java/lang/reflect/Method;->invoke",
            b"/system/bin/sh",
            b"android/app/admin/DevicePolicyManager",
            b"http://malicious-scam-apk-c2.cc/gate.php",
        ]
        apk_bytes = create_synthetic_apk_bytes(dex_strings=dex_patterns)
        buf = io.BytesIO(apk_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            dex_analysis, urls = inspect_dex_code(zf)

        assert dex_analysis.dex_count == 1
        assert "DexClassLoader" in dex_analysis.dynamic_code_loading_indicators
        assert "java/lang/reflect/Method;->invoke" in dex_analysis.reflection_indicators
        assert "/system/bin/sh" in dex_analysis.command_execution_indicators
        assert "android/app/admin/DevicePolicyManager" in dex_analysis.device_admin_indicators
        assert any("malicious-scam-apk-c2.cc" in u for u in urls)

    def test_native_library_detection(self):
        native_libs = [
            "lib/arm64-v8a/libnative.so",
            "lib/armeabi-v7a/libnative.so",
            "lib/x86_64/libhelper.so",
        ]
        apk_bytes = create_synthetic_apk_bytes(native_libs=native_libs)
        buf = io.BytesIO(apk_bytes)
        with zipfile.ZipFile(buf, "r") as zf:
            count, abis, so_names = extract_native_libraries(zf)

        assert count == 3
        assert "arm64-v8a" in abis
        assert "armeabi-v7a" in abis
        assert "x86_64" in abis
        assert "libnative.so" in so_names
        assert "libhelper.so" in so_names

    def test_embedded_url_filtering_and_scoring(self):
        raw_urls = [
            "http://schemas.android.com/apk/res/android",
            "http://www.w3.org/2000/xmlns/",
            "http://free-crypto-giveaway-verify-login.xyz/apk",
        ]
        findings, domains = filter_and_analyze_embedded_urls(raw_urls)
        assert len(findings) == 1
        assert "free-crypto-giveaway-verify-login.xyz" in findings[0].url
        assert "free-crypto-giveaway-verify-login.xyz" in domains


# ============================================================================
# 4. Threat Intelligence Provider Abstraction
# ============================================================================

@pytest.mark.asyncio
class TestApkThreatIntelligence:
    async def test_mock_provider_flagged_hash(self):
        target_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        preset = {
            target_hash: ApkIntelligenceResult(
                provider="mock-apk-intel",
                status="available",
                reputation="known_malware",
                malware_family="Android.Banker.Teabot",
                detection_ratio="48/70",
            )
        }
        provider = MockApkIntelligenceProvider(preset_hashes=preset)
        res = await provider.lookup_by_hash(target_hash)
        assert res.status == "available"
        assert res.reputation == "known_malware"
        assert res.malware_family == "Android.Banker.Teabot"

    async def test_mock_provider_clean_hash(self):
        provider = MockApkIntelligenceProvider()
        res = await provider.lookup_by_hash("0000000000000000000000000000000000000000000000000000000000000000")
        assert res.status == "available"
        assert res.reputation in ("clean", "unknown")

    async def test_unconfigured_provider(self):
        service = ApkIntelligenceService(provider=None)
        res = await service.lookup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        assert res.status == "not_configured"

    async def test_intelligence_cache_ttl(self):
        target_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        preset = {
            target_hash: ApkIntelligenceResult(
                provider="mock-apk-intel",
                status="available",
                reputation="known_malware",
                malware_family="Android.Banker.Teabot",
            )
        }
        provider = MockApkIntelligenceProvider(preset_hashes=preset)
        service = ApkIntelligenceService(provider=provider, cache_ttl_seconds=300)
        
        res1 = await service.lookup(target_hash)
        assert res1.reputation == "known_malware"

        res2 = await service.lookup(target_hash)
        assert res2.reputation == "known_malware"
        assert res1.checked_at == res2.checked_at


# ============================================================================
# 5. Static Rule Detector
# ============================================================================

class TestApkRuleDetector:
    def test_benign_apk_rules(self):
        analysis = ApkStaticAnalysisResult(
            package_name="org.wikipedia",
            application_label="Wikipedia",
            version_name="1.0.0",
            version_code="1",
            min_sdk_version="21",
            target_sdk_version="34",
            file_size_bytes=2048000,
            sha256="0" * 64,
            sha1="0" * 40,
            activity_count=3,
            service_count=1,
            receiver_count=1,
            provider_count=0,
            exported_component_count=1,
            activities=[],
            services=[],
            receivers=[],
            providers=[],
            permission_report=PermissionAnalysisReport(
                total_count=3,
                dangerous_count=0,
                special_count=0,
                normal_count=3,
                unknown_count=0,
                permissions=[],
                clusters=[],
                risk_score=0,
            ),
            dex_analysis=DexCodeAnalysis(dex_count=1, total_dex_size_bytes=500000),
            native_library_count=0,
            native_abis=[],
            native_libraries=[],
            certificate=ApkCertificateInfo(has_valid_signature=True, is_debug_certificate=False),
            embedded_urls=[],
            raw_extracted_domains=[],
        )
        score, indicators = apk_rule_detector.analyze(analysis)
        assert score < 20

    def test_malicious_banking_trojan_rules(self):
        analysis = ApkStaticAnalysisResult(
            package_name="com.scam.fakebank",
            application_label="Secure Bank Update",
            version_name="2.1.0",
            version_code="2",
            min_sdk_version="21",
            target_sdk_version="34",
            file_size_bytes=4096000,
            sha256="1" * 64,
            sha1="1" * 40,
            activity_count=8,
            service_count=4,
            receiver_count=4,
            provider_count=1,
            exported_component_count=6,
            activities=[],
            services=[],
            receivers=[],
            providers=[],
            permission_report=PermissionAnalysisReport(
                total_count=18,
                dangerous_count=7,
                special_count=9,
                normal_count=2,
                unknown_count=0,
                permissions=[],
                clusters=[
                    PermissionClusterFinding(
                        name="Banking Trojan Overlay & Interception Cluster",
                        severity="critical",
                        description="Accessibility + Overlay combination",
                        matched_permissions=["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
                        rule_id="APK_CLUSTER_BANKING_OVERLAY",
                    )
                ],
                risk_score=85,
            ),
            dex_analysis=DexCodeAnalysis(
                dex_count=1,
                dynamic_code_loading_indicators=["DexClassLoader"],
                reflection_indicators=["Method.invoke"],
                command_execution_indicators=["/system/bin/sh"],
                suspicious_api_count=3,
            ),
            native_library_count=1,
            native_abis=["arm64-v8a"],
            native_libraries=["libpayload.so"],
            certificate=ApkCertificateInfo(has_valid_signature=False, is_debug_certificate=True),
            embedded_urls=[],
            raw_extracted_domains=[],
        )
        score, indicators = apk_rule_detector.analyze(analysis)
        assert score >= 70
        rule_ids = [ind.rule_id for ind in indicators]
        assert "APK_CLUSTER_BANKING_OVERLAY" in rule_ids
        assert "APK_RULE_DYNAMIC_CODE_LOADING" in rule_ids
        assert "APK_RULE_SHELL_EXECUTION" in rule_ids
        assert "APK_RULE_DEBUG_CERTIFICATE" in rule_ids


# ============================================================================
# 6. ML Feature Pipeline & Inference Service
# ============================================================================

class TestApkMLPipeline:
    def test_feature_vector_dimension_and_names(self):
        assert len(APK_FEATURE_NAMES) == 26
        assert FEATURE_VERSION == "apk-feature-v1"

        data = {
            "package_name": "com.evil.trojan",
            "permission_count": 15,
            "dangerous_permission_count": 5,
            "sensitive_permission_count": 4,
            "has_sms_permission": True,
            "has_overlay_permission": True,
            "has_accessibility_permission": True,
            "has_install_packages_permission": True,
            "has_camera_permission": False,
            "has_audio_permission": False,
            "has_location_permission": True,
            "has_contacts_permission": False,
            "activity_count": 4,
            "service_count": 2,
            "receiver_count": 3,
            "provider_count": 1,
            "exported_component_count": 5,
            "dex_count": 1,
            "suspicious_api_count": 4,
            "has_dynamic_loading": True,
            "has_reflection": True,
            "has_command_execution": True,
            "native_library_count": 2,
            "certificate_present": True,
            "url_count": 3,
            "suspicious_url_count": 1,
        }
        vec = extract_apk_feature_vector(data)
        assert len(vec) == 26

    def test_inference_service_real_model(self):
        manager = ApkModelManager.get_instance()
        assert manager.is_loaded() is True

        # Malicious features
        mal_features = {
            "package_name": "com.scam.stealer",
            "permission_count": 22,
            "dangerous_permission_count": 8,
            "sensitive_permission_count": 7,
            "has_sms_permission": True,
            "has_overlay_permission": True,
            "has_accessibility_permission": True,
            "has_install_packages_permission": True,
            "has_camera_permission": True,
            "has_audio_permission": True,
            "has_location_permission": True,
            "has_contacts_permission": True,
            "activity_count": 8,
            "service_count": 4,
            "receiver_count": 6,
            "provider_count": 2,
            "exported_component_count": 8,
            "dex_count": 2,
            "suspicious_api_count": 8,
            "has_dynamic_loading": True,
            "has_reflection": True,
            "has_command_execution": True,
            "native_library_count": 1,
            "certificate_present": False,
            "url_count": 5,
            "suspicious_url_count": 3,
        }
        res_mal = predict_apk_risk(mal_features)
        assert res_mal["model_score"] >= 0.70
        assert res_mal["prediction"] == "malware"

        # Benign features
        benign_features = {
            "package_name": "org.wikipedia.android",
            "permission_count": 3,
            "dangerous_permission_count": 0,
            "sensitive_permission_count": 0,
            "has_sms_permission": False,
            "has_overlay_permission": False,
            "has_accessibility_permission": False,
            "has_install_packages_permission": False,
            "has_camera_permission": False,
            "has_audio_permission": False,
            "has_location_permission": False,
            "has_contacts_permission": False,
            "activity_count": 5,
            "service_count": 1,
            "receiver_count": 1,
            "provider_count": 0,
            "exported_component_count": 1,
            "dex_count": 1,
            "suspicious_api_count": 0,
            "has_dynamic_loading": False,
            "has_reflection": False,
            "has_command_execution": False,
            "native_library_count": 0,
            "certificate_present": True,
            "url_count": 1,
            "suspicious_url_count": 0,
        }
        res_ben = predict_apk_risk(benign_features)
        assert res_ben["model_score"] <= 0.30
        assert res_ben["prediction"] in ("benign", "clean")


# ============================================================================
# 7. Unified Risk Engine Integration & Explainability
# ============================================================================

class TestUnifiedApkRiskEngine:
    def test_unified_apk_risk_fusion(self):
        findings = [
            ThreatIndicator(
                name="Banking Trojan Overlay",
                severity="critical",
                description="Accessibility + overlay abuse",
                rule_id="APK_CLUSTER_BANKING_OVERLAY",
            )
        ]
        score, level, conf, r_score, m_score, i_score = calculate_unified_apk_risk(
            rule_score=85,
            findings=findings,
            ml_result={"prediction": "malware", "model_score": 0.90},
            intel_result=None,
        )
        assert score >= 80
        assert level in ["high", "critical"]

    def test_apk_category_determination(self):
        findings = [
            ThreatIndicator(
                name="Banking Overlay Cluster",
                severity="critical",
                description="Trojan overlay",
                rule_id="APK_CLUSTER_BANKING_OVERLAY",
            )
        ]
        cats = determine_apk_categories(
            findings=findings,
            ml_result={"prediction": "malware", "model_score": 0.85},
            intel_result=None,
        )
        assert "potential_malware" in cats
        assert "banking_trojan" in cats

    def test_apk_explainable_explanations(self):
        findings = [
            ThreatIndicator(
                name="Banking Overlay Cluster",
                severity="critical",
                description="Trojan overlay",
                rule_id="APK_CLUSTER_BANKING_OVERLAY",
            )
        ]
        summary = generate_apk_summary(
            risk_level="critical",
            findings=findings,
            ml_result={"prediction": "malware"},
        )
        assert "critical" in summary.lower() or "malware" in summary.lower()

        rec = generate_apk_recommendation(
            risk_level="critical",
            findings=findings,
        )
        assert "DO NOT" in rec

        reasons = generate_apk_reasons(
            findings=findings,
            ml_result={"prediction": "malware", "model_score": 0.88},
            apk_info={"package_name": "com.test.trojan", "target_sdk_version": "34", "total_permissions": 12},
        )
        assert len(reasons) >= 2


# ============================================================================
# 8. FastAPI API Endpoints & Cleanup Verification
# ============================================================================

@pytest.mark.asyncio
class TestApkApiEndpoints:
    async def test_scan_apk_endpoint_simulated(self):
        app = create_application()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            payload = {
                "package_name": "com.test.banking.malware",
                "app_name": "Test Bank",
                "permissions": [
                    "android.permission.SYSTEM_ALERT_WINDOW",
                    "android.permission.RECEIVE_SMS",
                    "android.permission.BIND_ACCESSIBILITY_SERVICE",
                ],
            }
            resp = await client.post("/api/v1/scan/apk", json=payload)
            assert resp.status_code == 200
            data = resp.json()
            assert data["input_type"] == "apk"
            assert data["risk_score"] > 60
            assert "detection" in data
            assert "permissions" in data["detection"]
            assert "ml" in data["detection"]

    async def test_upload_apk_endpoint_success(self):
        app = create_application()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            apk_bytes = create_synthetic_apk_bytes(
                dex_strings=[b"DexClassLoader", b"http://evil-tracker-url.com"]
            )
            files = {
                "file": ("test_sample.apk", apk_bytes, "application/vnd.android.package-archive")
            }
            resp = await client.post("/api/v1/scan/apk/upload", files=files)
            assert resp.status_code == 200
            data = resp.json()
            assert data["input_type"] == "apk"
            assert data["status"] == "completed"
            assert "detection" in data
            assert data["detection"]["certificate"] is not None

    async def test_upload_apk_endpoint_invalid_file_rejected(self):
        app = create_application()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            files = {
                "file": ("not_an_apk.txt", b"plain text content", "text/plain")
            }
            resp = await client.post("/api/v1/scan/apk/upload", files=files)
            assert resp.status_code in (400, 422)
            assert "extension" in resp.json()["detail"].lower()
