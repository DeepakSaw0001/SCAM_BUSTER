"""
ScamBuster Phase 09 — Web Security, Redirect & Download Pipeline Tests

Comprehensive automated test suite covering:
1. SSRF Security & Private Network Defense (Mandatory)
2. DNS Rebinding Protections
3. Redirect Chain, Loop, and Limit Enforcement
4. HTML Structure, Forms & Credential Exposure Detection
5. Download & Payload Analysis (MIME, Magic Bytes, Hashes)
6. APK Handoff & Static Analysis Integration
7. Unified Risk Engine & Web Rule Evaluation
"""

import io
import os
import tempfile
import zipfile
import pytest
from unittest.mock import patch, MagicMock

from app.services.web_analysis.security_policy import (
    is_hostname_prohibited,
    is_ip_prohibited,
    resolve_and_validate_destination,
    validate_web_fetch_url,
)
from app.services.web_analysis.redirect_analyzer import (
    RedirectTracker,
    extract_registrable_domain,
)
from app.services.web_analysis.response_analyzer import (
    analyze_http_response,
    analyze_security_headers,
)
from app.services.web_analysis.content_analyzer import (
    analyze_html_content,
    SafeContentParser,
)
from app.services.web_analysis.download_analyzer import (
    inspect_download_metadata,
    analyze_downloaded_payload,
)
from app.services.web_risk_rules import evaluate_web_risk_rules
from app.risk_engine.scorer import calculate_unified_url_and_web_risk
from app.ml.web_inference import WebRiskModelManager, predict_web_risk


# ============================================================================
# 1. SSRF & PRIVATE NETWORK SECURITY TESTS (MANDATORY)
# ============================================================================

class TestSsrfDefense:
    """Verifies that ScamBuster strictly prohibits access to internal or reserved networks."""

    @pytest.mark.parametrize("blocked_url", [
        "http://localhost:8000/keys",
        "http://127.0.0.1/admin",
        "http://127.0.0.2:8080/",
        "http://10.0.0.1/",
        "http://10.254.1.1/secret",
        "http://172.16.0.1/",
        "http://172.31.255.255/",
        "http://192.168.0.1/",
        "http://192.168.1.254/router",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fc00::1]/",
        "http://[fe80::1]/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://instance-data/latest/meta-data/",
        "http://server.local/",
        "http://database.internal/",
    ])
    def test_ssrf_prohibited_destinations_blocked(self, blocked_url):
        is_safe, reason, _, _ = validate_web_fetch_url(blocked_url)
        assert not is_safe, f"SSRF security breach! URL should be blocked: {blocked_url}"
        assert len(reason) > 0

    def test_dns_rebinding_defense_catches_private_ip(self):
        """Simulate DNS returning a public hostname that resolves to a private IP (rebinding attempt)."""
        with patch("socket.getaddrinfo") as mock_dns:
            # Simulate attacker.com resolving to 192.168.1.1
            mock_dns.return_value = [
                (2, 1, 6, "", ("192.168.1.1", 80))
            ]
            is_safe, reason, resolved = resolve_and_validate_destination("attacker.com", 80)
            assert not is_safe
            assert "DNS rebinding" in reason or "prohibited" in reason.lower()
            assert "192.168.1.1" in resolved

    def test_prohibited_scheme(self):
        """Verify non-HTTP/HTTPS schemes (file, gopher, ftp, dict) are rejected."""
        assert not validate_web_fetch_url("file:///etc/passwd")[0]
        assert not validate_web_fetch_url("gopher://127.0.0.1:70/")[0]
        assert not validate_web_fetch_url("ftp://legit.com/file")[0]


# ============================================================================
# 2. REDIRECT ANALYSIS TESTS
# ============================================================================

class TestRedirectAnalysis:
    """Verifies redirect tracking, loop prevention, cross-domain flags, and limits."""

    def test_single_and_cross_domain_redirect(self):
        tracker = RedirectTracker("https://short.ly/abc")
        cont, reason = tracker.add_hop("https://short.ly/abc", "https://final-destination.com/home", 302)
        assert cont is True
        summary = tracker.get_summary("https://final-destination.com/home")

        assert summary["redirect_count"] == 1
        assert summary["cross_domain_count"] == 1
        assert summary["has_cross_domain"] is True
        assert summary["loop_detected"] is False

    def test_redirect_loop_detection(self):
        """Verify circular redirection A -> B -> A halts execution."""
        tracker = RedirectTracker("https://a.com/start")
        tracker.add_hop("https://a.com/start", "https://b.com/middle", 302)
        cont, reason = tracker.add_hop("https://b.com/middle", "https://a.com/start", 302)

        assert cont is False
        assert "loop detected" in reason.lower()
        assert tracker.loop_detected is True

    def test_domain_hopping_detection(self):
        """Verify hops across >= 3 distinct domains triggers domain_hopping."""
        tracker = RedirectTracker("https://hop1.com/a")
        tracker.add_hop("https://hop1.com/a", "https://hop2.net/b", 302)
        tracker.add_hop("https://hop2.net/b", "https://hop3.org/c", 302)
        tracker.add_hop("https://hop3.org/c", "https://hop4.top/d", 302)

        summary = tracker.get_summary("https://hop4.top/d")
        assert summary["domain_hopping"] is True
        assert summary["distinct_domain_count"] >= 3

    def test_meta_refresh_extraction(self):
        tracker = RedirectTracker("https://example.com/gate")
        html = '<html><head><meta http-equiv="refresh" content="3;url=https://target.com/login"></head></html>'
        meta = tracker.analyze_html_redirects(html, "https://example.com/gate")

        assert meta is not None
        assert meta["type"] == "META_REFRESH"
        assert meta["target_url"] == "https://target.com/login"
        assert tracker.meta_refresh_detected is True

    def test_static_js_redirect_extraction(self):
        tracker = RedirectTracker("https://example.com/landing")
        html = '<script>window.location.href = "https://phishing.xyz/verify";</script>'
        js = tracker.analyze_html_redirects(html, "https://example.com/landing")

        assert js is not None
        assert js["type"] == "JAVASCRIPT_LOCATION"
        assert "phishing.xyz" in js["target_url"]
        assert tracker.js_redirect_detected is True


# ============================================================================
# 3. HTML & CONTENT ANALYSIS TESTS
# ============================================================================

class TestContentAnalysis:
    """Verifies safe HTML extraction of title, credential forms, and iframes."""

    def test_login_form_extraction(self):
        html = """
        <html>
        <head><title>Secure Banking Login</title></head>
        <body>
            <form action="/auth/verify" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" id="user_pwd" />
                <button type="submit">Sign In</button>
            </form>
        </body>
        </html>
        """
        res = analyze_html_content(html, "https://fakebank.com/login")
        assert res["title"] == "Secure Banking Login"
        assert res["form_count"] == 1
        assert res["password_form_count"] == 1
        assert res["has_credential_form"] is True

    def test_payment_and_otp_form_extraction(self):
        html = """
        <form action="/pay">
            <input type="text" name="cc_number" id="card_number" />
            <input type="text" name="card_cvv" />
            <input type="text" name="sms_otp" />
        </form>
        """
        res = analyze_html_content(html, "https://payportal.xyz")
        assert res["payment_form_count"] >= 1
        assert res["otp_form_count"] >= 1
        assert res["has_credential_form"] is True

    def test_hidden_and_cross_domain_iframe(self):
        html = """
        <html>
        <body>
            <iframe src="https://tracker.com/pixel" style="display:none; width:0; height:0;"></iframe>
            <iframe src="/internal/help" width="500" height="300"></iframe>
        </body>
        </html>
        """
        res = analyze_html_content(html, "https://mysite.com")
        assert res["iframe_count"] == 2
        assert res["hidden_iframe_count"] == 1
        assert res["cross_domain_iframe_count"] == 1

    def test_obfuscation_primitives_detection(self):
        html = "<script>eval(String.fromCharCode(97, 108, 101, 114, 116));</script>"
        res = analyze_html_content(html, "https://obf.example.com")
        assert len(res["obfuscation_indicators"]) > 0


# ============================================================================
# 4. DOWNLOAD & PAYLOAD ANALYSIS TESTS
# ============================================================================

class TestDownloadAnalysis:
    """Verifies download initiation detection, file typing, magic bytes, and hashing."""

    def test_content_disposition_attachment(self):
        headers = {
            "Content-Disposition": 'attachment; filename="setup_installer.exe"',
            "Content-Type": "application/octet-stream",
        }
        res = inspect_download_metadata("https://cdn.example.com/get", headers, b"MZ\x90\x00")
        assert res["download_detected"] is True
        assert res["is_attachment"] is True
        assert res["file_type"] == "EXE"
        assert res["is_executable"] is True

    def test_apk_download_detection_and_magic_bytes(self):
        headers = {
            "Content-Type": "application/vnd.android.package-archive",
        }
        res = inspect_download_metadata("https://apps.store.xyz/app.apk", headers, b"PK\x03\x04")
        assert res["download_detected"] is True
        assert res["is_apk"] is True
        assert res["file_type"] == "APK"

    def test_sha256_calculation_and_sizing(self):
        dummy_data = b"Hello ScamBuster Web Download"
        meta = {
            "download_detected": True,
            "filename": "sample.pdf",
            "file_type": "PDF",
            "extension": ".pdf",
            "is_executable": False,
            "is_apk": False,
        }
        payload_res = analyze_downloaded_payload(dummy_data, meta, "https://example.com/doc.pdf")
        assert payload_res["file_size_bytes"] == len(dummy_data)
        assert len(payload_res["sha256"]) == 64
        assert not payload_res["oversized"]


# ============================================================================
# 5. INTEGRATION: URL -> DOWNLOAD -> APK STATIC ANALYZER (PHASE 07/08 HANDOFF)
# ============================================================================

class TestApkDownloadHandoffIntegration:
    """
    Verifies that a detected APK download is passed safely into Phase 07/08
    static analysis without code execution.
    """

    def test_apk_download_static_analysis_handoff(self):
        # Create a valid minimal ZIP with AndroidManifest.xml dummy inside
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("AndroidManifest.xml", b"<manifest package='com.phish.drop'/>")
            zf.writestr("classes.dex", b"DEX DATA")
        apk_bytes = zip_buffer.getvalue()

        meta = {
            "download_detected": True,
            "filename": "payload.apk",
            "file_type": "APK",
            "extension": ".apk",
            "is_executable": False,
            "is_apk": True,
        }

        # Analyze downloaded payload
        res = analyze_downloaded_payload(apk_bytes, meta, "https://malicious-drop.xyz/app.apk")
        assert res["is_apk"] is True
        assert res["apk_analysis"] is not None
        assert res["apk_analysis"]["status"] in ("analyzed", "analysis_failed")
        # Verify package hash is computed
        assert len(res["sha256"]) == 64


# ============================================================================
# 6. WEB RISK RULES & UNIFIED RISK ENGINE TESTS
# ============================================================================

class TestWebRiskRulesAndScoring:
    """Verifies rule triggering, indicator production, and Risk Engine fusion."""

    def test_rules_trigger_on_domain_hopping_and_form(self):
        web_analysis = {
            "status": "completed",
            "redirects": {
                "domain_hopping": True,
                "distinct_domain_count": 4,
                "chain": [
                    {"target_domain": "a.com"},
                    {"target_domain": "b.net"},
                    {"target_domain": "c.top"},
                ],
            },
            "response": {"is_https": False},
            "content": {
                "has_credential_form": True,
                "password_form_count": 1,
                "payment_form_count": 0,
            },
            "download": None,
        }
        score, indicators = evaluate_web_risk_rules(web_analysis, existing_url_score=20)
        assert score >= 50
        rule_ids = {ind["rule_id"] for ind in indicators}
        assert "WEB_RULE_DOMAIN_HOPPING" in rule_ids
        assert "WEB_RULE_UNENCRYPTED_CREDENTIAL_FORM" in rule_ids

    def test_ssrf_rule_triggers_critical_score(self):
        web_analysis = {
            "status": "blocked",
            "failure_reason": "SSRF Security Violation: Loopback address prohibited: 127.0.0.1",
        }
        score, indicators = evaluate_web_risk_rules(web_analysis)
        assert score >= 80
        assert indicators[0]["severity"] == "CRITICAL"
        assert indicators[0]["rule_id"] == "WEB_RULE_SSRF_BLOCKED"

    def test_unified_url_and_web_risk_fusion(self):
        """Test fusion of clean URL lexical rules + High risk Web rules."""
        url_findings = []  # Clean lexical URL
        web_findings = [
            {
                "rule_id": "WEB_RULE_DOWNLOAD_EXECUTABLE",
                "name": "Executable Download",
                "severity": "high",
                "description": "Windows installer downloaded.",
            }
        ]
        web_ml_res = {
            "available": True,
            "prediction": "malicious",
            "model_score": 0.85,
        }

        composite, level, conf, lex_s, web_s, ml_s = calculate_unified_url_and_web_risk(
            url_findings=url_findings,
            url_ml_result=None,
            web_findings=web_findings,
            web_ml_result=web_ml_res,
            download_analysis={"is_executable": True},
        )

        assert composite >= 60
        assert level in ("high", "critical")
        assert conf >= 0.80


# ============================================================================
# 7. ML INFERENCE SERVICE TESTS
# ============================================================================

class TestWebRiskMlInference:
    """Verifies that the trained ML model loads and classifies web feature vectors."""

    def test_inference_service_loaded(self):
        mgr = WebRiskModelManager.get_instance()
        assert mgr.is_loaded() is True
        assert mgr.model_version == "web_model_v1.0"

    def test_predict_benign_profile(self):
        benign_analysis = {
            "redirects": {"redirect_count": 0, "cross_domain_count": 0, "has_cross_domain": False},
            "response": {"is_https": True, "security_headers": {"hardening_score": 90}},
            "content": {"has_credential_form": False, "form_count": 1},
            "download": {"download_detected": False},
        }
        res = predict_web_risk(benign_analysis)
        assert res["available"] is True
        assert res["prediction"] in ("benign", "suspicious", "phishing", "malicious")
        assert "top_contributing_features" in res
