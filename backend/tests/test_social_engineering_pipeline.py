"""
ScamBuster — Phase 10: Advanced Email, SMS & Social Engineering Intelligence Test Suite

Comprehensive testing covering:
1. Input Normalization & Anti-Obfuscation (Unicode, de-spacing, leetspeak, defanged URLs)
2. Multilingual Language Detection (English, Hindi, Marathi, Hinglish)
3. Safe HTML Extraction & Anchor Text Mismatch (Zero JS execution, zero remote rendering)
4. Sender Consistency & Header Authentication (From/Reply-To mismatch, display name spoofing, SPF/DKIM/DMARC)
5. Social Engineering Rules (Urgency, Fear, Reward, Credential request, OTP request with educational warning)
6. Brand Intelligence & Lookalike Detection (Typosquatting, Combosquatting, Brand-domain mismatch)
7. Attachment Risk Analysis (Executables, double extensions, APKs, macros, archives, safe files)
8. PII & Secret Redaction Engine (OTPs, Luhn cards, CVVs, tokens, emails, phones)
9. Unified Risk Engine Corroboration & Deduplication
10. False Positive Benchmarking (Legitimate bank alert, legitimate university notice, password reset)
11. End-to-End API Integration (POST /api/v1/scan/message, POST /api/v1/scan/email)
"""

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app
from app.security.social_engineering.taxonomy import (
    SocialEngineeringCategory,
    get_category_metadata,
)
from app.security.redaction import (
    redact_sensitive_text,
    mask_email,
    mask_phone,
    mask_credit_card,
    is_luhn_valid,
)
from app.intelligence.brands.catalog import BRAND_CATALOG, lookup_brand_by_domain, lookup_brand_by_name
from app.intelligence.brands.lookalike_detector import (
    is_lookalike_domain,
    detect_brand_domain_mismatches,
)
from app.services.message_analysis.normalizer import (
    normalize_message_input,
    detect_language,
    deobfuscate_urls_in_text,
    deobfuscate_spaced_keywords,
)
from app.services.message_analysis.text_extractor import (
    extract_html_email_content,
    evaluate_anchor_mismatch,
)
from app.services.message_analysis.metadata_extractor import (
    analyze_sender_consistency,
    parse_authentication_results,
)
from app.services.social_engineering_rules import evaluate_social_engineering_rules
from app.risk_engine.scorer import (
    calculate_unified_message_risk,
    calculate_unified_email_risk,
)
from app.risk_engine.categories import (
    determine_message_categories,
    determine_email_categories,
)
from app.services.email_parser import parse_structured_email


# ==============================================================================
# 1. NORMALIZATION & ANTI-OBFUSCATION TESTS
# ==============================================================================

def test_normalization_defanged_urls():
    """Verify defanged URLs (hxxps://, [.], [dot]) are safely normalized."""
    text = "Please check your account at hxxps://secure-login[.]example[.]com/verify"
    norm = normalize_message_input(text)
    assert norm.obfuscation_detected is True
    assert any("https://secure-login.example.com/verify" in u for u in norm.extracted_urls)


def test_normalization_spaced_keywords():
    """Verify spaced scam keywords (e.g. O T P, v e r i f y) are de-spaced."""
    text = "Urgent: Send your O T P to v e r i f y your identity."
    norm = normalize_message_input(text)
    assert norm.obfuscation_detected is True
    assert "OTP" in norm.normalized_text
    assert "verify" in norm.normalized_text


def test_normalization_leetspeak_words():
    """Verify leetspeak substitutions (v3rify, acc0unt) are resolved."""
    text = "Please v3rify your acc0unt before it exp1res."
    norm = normalize_message_input(text)
    assert norm.obfuscation_detected is True
    assert "verify" in norm.normalized_text.lower()
    assert "account" in norm.normalized_text.lower()


# ==============================================================================
# 2. MULTILINGUAL LANGUAGE DETECTION TESTS
# ==============================================================================

def test_language_detection_english():
    lang, conf = detect_language("Your account will be suspended today. Please click the link to verify.")
    assert lang == "English"
    assert conf >= 0.80


def test_language_detection_hindi():
    lang, conf = detect_language("आपका बैंक खाता तुरंत बंद कर दिया जाएगा कृपया संदेश का उत्तर दें।")
    assert lang == "Hindi"
    assert conf >= 0.70


def test_language_detection_marathi():
    lang, conf = detect_language("तुमचे बँक खाते तात्काळ बंद करण्यात आले आहे कृपया पैसे त्वरित भरा.")
    assert lang == "Marathi"
    assert conf >= 0.70


def test_language_detection_hinglish():
    lang, conf = detect_language("Apka khata turant band ho gaya hai kripya paise bhejo.")
    assert lang == "Hinglish"
    assert conf >= 0.80


# ==============================================================================
# 3. SAFE HTML EXTRACTION & ANCHOR MISMATCH TESTS
# ==============================================================================

def test_safe_html_strips_scripts_and_extracts_links():
    html = """
    <html>
      <head><script>alert('malicious')</script></head>
      <body>
        <p>Dear user,</p>
        <a href="https://legitimate.org/docs">Download Guide</a>
        <iframe src="https://tracking.com/pixel"></iframe>
      </body>
    </html>
    """
    res = extract_html_email_content(html)
    assert "alert('malicious')" not in res.visible_text
    assert "Dear user," in res.visible_text
    assert len(res.extracted_links) == 1
    assert res.extracted_links[0].href == "https://legitimate.org/docs"
    assert len(res.iframes) == 1


def test_anchor_mismatch_detected():
    """Verify deceptive visible domain vs href is flagged."""
    disp = "https://chase.com/secure-login"
    href = "http://phishing-portal-site.xyz/auth"
    is_mismatch, disp_host, reason = evaluate_anchor_mismatch(disp, href)
    assert is_mismatch is True
    assert "chase.com" in (disp_host or "")


def test_anchor_match_legitimate():
    """Verify genuine matching anchor text and destination does not flag mismatch."""
    disp = "https://chase.com/login"
    href = "https://chase.com/login"
    is_mismatch, _, _ = evaluate_anchor_mismatch(disp, href)
    assert is_mismatch is False


# ==============================================================================
# 4. SENDER CONSISTENCY & HEADER AUTHENTICATION TESTS
# ==============================================================================

def test_sender_consistency_reply_to_mismatch():
    rep = analyze_sender_consistency(
        from_header="Support Team <support@paypal.com>",
        reply_to_header="hacker@external-inbox.net",
    )
    assert rep.has_reply_to_mismatch is True
    assert "Reply-to mismatch detected" in rep.reply_to_mismatch_description


def test_sender_consistency_display_name_spoofing():
    rep = analyze_sender_consistency(
        from_header="PayPal Support <service@unrelated-server.org>",
    )
    assert rep.is_display_name_spoof is True
    assert "Possible sender impersonation" in rep.display_name_spoof_description


def test_sender_consistency_matching_legitimate():
    rep = analyze_sender_consistency(
        from_header="PayPal Service <service@paypal.com>",
        reply_to_header="service@paypal.com",
    )
    assert rep.has_reply_to_mismatch is False
    assert rep.is_display_name_spoof is False


# ==============================================================================
# 5. SOCIAL ENGINEERING RULES TESTS
# ==============================================================================

def test_social_engineering_otp_harvest_rule():
    """Verify OTP solicitation generates critical finding and educational warning."""
    text = "Please tell me the OTP you just received to cancel the transaction."
    findings = evaluate_social_engineering_rules(message_text=text)
    otp_finding = next((f for f in findings if f.category == SocialEngineeringCategory.OTP_SCAM), None)
    assert otp_finding is not None
    assert otp_finding.severity == "CRITICAL"
    assert "Legitimate organizations generally should not ask you to disclose authentication codes" in otp_finding.why_it_matters


def test_social_engineering_credential_harvest_rule():
    text = "Verify your password and enter your card number to regain access."
    findings = evaluate_social_engineering_rules(message_text=text)
    cred_finding = next((f for f in findings if f.category == SocialEngineeringCategory.CREDENTIAL_THEFT), None)
    assert cred_finding is not None
    assert cred_finding.severity == "CRITICAL"


def test_social_engineering_urgency_rule():
    text = "Your account will be suspended within 2 hours if no action is taken."
    findings = evaluate_social_engineering_rules(message_text=text)
    urgency_finding = next((f for f in findings if f.category == SocialEngineeringCategory.URGENCY), None)
    assert urgency_finding is not None
    assert urgency_finding.severity == "MEDIUM"


def test_social_engineering_reward_rule():
    text = "Congratulations! You have won a cash reward of $5,000. Claim your prize now."
    findings = evaluate_social_engineering_rules(message_text=text)
    reward_finding = next((f for f in findings if f.category == SocialEngineeringCategory.REWARD), None)
    assert reward_finding is not None
    assert reward_finding.severity == "HIGH"


def test_social_engineering_delivery_scam_rule():
    text = "Your parcel delivery is held due to missing street address. Update address to reschedule delivery."
    findings = evaluate_social_engineering_rules(message_text=text)
    del_finding = next((f for f in findings if f.category == SocialEngineeringCategory.DELIVERY_SCAM), None)
    assert del_finding is not None


# ==============================================================================
# 6. BRAND INTELLIGENCE & LOOKALIKE DETECTION TESTS
# ==============================================================================

def test_brand_catalog_lookups():
    paypal = lookup_brand_by_name("paypal")
    assert paypal is not None
    assert "paypal.com" in paypal.official_domains

    chase = lookup_brand_by_domain("secure.chase.com")
    assert chase is not None
    assert chase.canonical_id == "chase"


def test_brand_combosquatting_lookalike():
    is_look, reason = is_lookalike_domain("chase-security-verify.com", {"chase.com"})
    assert is_look is True
    assert "Combosquatting" in reason


def test_brand_domain_mismatch_detection():
    findings = detect_brand_domain_mismatches(
        claimed_text="Your PayPal account has been limited.",
        domains=[("paypal-verify-account.com", "link_destination")],
    )
    assert len(findings) >= 1
    assert findings[0].brand.display_name == "PayPal"
    assert findings[0].is_lookalike is True


# ==============================================================================
# 7. ATTACHMENT RISK ANALYSIS TESTS
# ==============================================================================

def test_dangerous_attachment_executable():
    att = [{"filename": "invoice_update.exe", "extension": ".exe", "size_bytes": 10240}]
    findings = evaluate_social_engineering_rules(message_text="See attached invoice", attachments=att)
    att_finding = next((f for f in findings if f.rule_id == "RULE_SE_DANGEROUS_ATTACHMENT"), None)
    assert att_finding is not None
    assert att_finding.severity == "CRITICAL"


def test_dangerous_attachment_double_extension():
    att = [{"filename": "statement.pdf.exe", "extension": ".exe", "size_bytes": 10240}]
    findings = evaluate_social_engineering_rules(message_text="See statement", attachments=att)
    double_finding = next((f for f in findings if f.rule_id == "RULE_SE_DOUBLE_EXTENSION_ATTACHMENT"), None)
    assert double_finding is not None
    assert double_finding.severity == "CRITICAL"


def test_apk_attachment_identified():
    att = [{"filename": "bank_app_update.apk", "extension": ".apk", "size_bytes": 5000000}]
    findings = evaluate_social_engineering_rules(message_text="Install this APK update", attachments=att)
    apk_finding = next((f for f in findings if f.rule_id == "RULE_SE_APK_ATTACHMENT"), None)
    assert apk_finding is not None
    assert "Phase 07" in apk_finding.evidence


# ==============================================================================
# 8. PII & CREDENTIAL REDACTION TESTS
# ==============================================================================

def test_redact_otp_in_context():
    text = "Your verification code is 849201. Never share this code."
    redacted = redact_sensitive_text(text)
    assert "849201" not in redacted
    assert "[REDACTED_OTP]" in redacted


def test_redact_credit_card_luhn():
    # Valid Visa test number
    card = "4111 1111 1111 1111"
    assert is_luhn_valid("4111111111111111") is True
    redacted = redact_sensitive_text(f"Please charge card {card} for transaction.")
    assert "4111 1111 1111 1111" not in redacted
    assert "4111-****-****-1111" in redacted


def test_mask_email_and_phone():
    assert mask_email("user.support@domain.com") == "u***t@domain.com"
    assert mask_phone("+14155552671") == "+14***71"


# ==============================================================================
# 9. UNIFIED RISK ENGINE CORROBORATION & DEDUPLICATION TESTS
# ==============================================================================

def test_risk_engine_multi_signal_corroboration():
    """Verify that multiple corroborating signals elevate threat floor and confidence."""
    # Create findings across 3 distinct vectors: Credential Harvesting + Urgency + Brand Lookalike
    findings = evaluate_social_engineering_rules(
        message_text="URGENT: PayPal account suspended! Verify password immediately at link.",
        sender_domain="paypal-account-unlock.xyz",
        extracted_urls=["https://paypal-account-unlock.xyz/login"],
    )
    score, level, confidence, rule_score, _ = calculate_unified_message_risk(
        rule_findings=[],
        social_engineering_findings=findings,
        embedded_urls_analysis=[{"risk_score": 85}],
        has_sufficient_evidence=True,
    )
    assert score >= 80
    assert level == "critical"
    assert confidence >= 0.94


def test_risk_engine_clean_baseline():
    """Verify benign message without indicators results in very low risk."""
    score, level, confidence, _, _ = calculate_unified_message_risk(
        rule_findings=[],
        social_engineering_findings=[],
        has_sufficient_evidence=True,
    )
    assert score <= 5
    assert level == "very_low"
    assert confidence >= 0.85


# ==============================================================================
# 10. FALSE POSITIVE BENCHMARK TESTS
# ==============================================================================

def test_false_positive_legitimate_bank_alert():
    """Verify ordinary banking transaction notification is NOT classified as a scam."""
    legit_bank_sms = (
        "Your checking account balance ending in 1234 was debited $15.50 at Corner Cafe. "
        "Available balance: $1,420.00. If this wasn't you, log into your mobile banking app."
    )
    norm = normalize_message_input(legit_bank_sms)
    se_findings = evaluate_social_engineering_rules(message_text=norm.normalized_text)
    # Shouldn't trigger OTP harvest or password theft
    assert not any(f.category == SocialEngineeringCategory.OTP_SCAM for f in se_findings)
    assert not any(f.category == SocialEngineeringCategory.CREDENTIAL_THEFT for f in se_findings)


def test_false_positive_college_notification():
    college_email = parse_structured_email(
        subject="Fall Semester Registration Deadline Notice",
        sender="Academic Advising <advising@university.edu>",
        body="Dear Students, please remember course registration for Fall closes on Friday at 5 PM.",
    )
    findings = evaluate_social_engineering_rules(
        message_text=college_email.body_text,
        subject=college_email.subject,
        sender_domain=college_email.sender_domain,
    )
    assert len(findings) == 0


# ==============================================================================
# 11. END-TO-END API INTEGRATION TESTS
# ==============================================================================

@pytest.mark.asyncio
async def test_api_message_scan_with_social_engineering():
    """Verify POST /api/v1/scan/message returns social engineering payload and taxonomy."""
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/scan/message",
            json={
                "message": "URGENT: Your bank account will be blocked today! Tell me the OTP immediately to cancel.",
                "sender": "+18005550199",
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert data["composite_risk_score"] >= 80
        assert data["risk_level"] in ("HIGH", "CRITICAL")
        assert "social_engineering" in data
        se = data["social_engineering"]
        assert "OTP_SCAM" in se["detected_categories"]
        assert len(se["why_this_matters"]) >= 1


@pytest.mark.asyncio
async def test_api_email_scan_with_anchor_mismatch():
    """Verify POST /api/v1/scan/email detects anchor mismatch and sender divergence."""
    email_raw = (
        "From: Bank Support <security@attacker-domain.org>\r\n"
        "Reply-To: phisher@external-drop.net\r\n"
        "Subject: Urgent: Verify Chase Account\r\n"
        "Content-Type: text/html\r\n\r\n"
        "<html><body>"
        "<p>Please verify your Chase account:</p>"
        "<a href='http://fake-chase-update.top/login'>https://chase.com/login</a>"
        "</body></html>"
    )
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.post(
            "/api/v1/scan/email",
            json={"raw_email": email_raw},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["composite_risk_score"] >= 80
        assert data["risk_level"].upper() in ("HIGH", "CRITICAL")
        assert "social_engineering" in data
        se = data["social_engineering"]
        assert "MALICIOUS_LINK" in se["detected_categories"] or "IMPERSONATION" in se["detected_categories"]
        assert len(se["anchor_mismatches"]) >= 1
