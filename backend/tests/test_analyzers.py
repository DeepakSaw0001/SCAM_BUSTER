"""
Unit Tests for ScamBuster Cybersecurity Heuristic Analyzers
"""

import pytest
from app.services.analyzers import (
    analyze_apk,
    analyze_email,
    analyze_phone,
    analyze_text,
    analyze_url,
)


def test_url_analyzer_benign():
    result = analyze_url("https://google.com/search?q=cybersecurity")
    assert result["score"] == 0
    assert len(result["indicators"]) == 0
    assert result["details"]["is_ip"] is False


def test_url_analyzer_malicious():
    # IP host + paypal brand impersonation + login keyword
    result = analyze_url("http://192.168.1.50/paypal/login.php?update=now")
    assert result["score"] >= 50
    indicator_names = [i["name"] for i in result["indicators"]]
    assert any("IP Address" in name for name in indicator_names)
    assert any("Paypal" in name for name in indicator_names)


def test_url_analyzer_suspicious_tld_and_shortener():
    result = analyze_url("http://account-verify-portal.xyz/claim")
    assert result["score"] >= 25
    indicator_names = [i["name"] for i in result["indicators"]]
    assert any("Top Level Domain" in name for name in indicator_names)


def test_text_analyzer_benign():
    result = analyze_text("Hey team, lunch meeting is postponed to 2pm tomorrow.")
    assert result["score"] == 0
    assert len(result["indicators"]) == 0


def test_text_analyzer_credential_and_urgency():
    result = analyze_text("URGENT: Your Chase account is suspended! Send your OTP code immediately to prevent arrest.")
    assert result["score"] >= 50
    indicator_severities = [i["severity"] for i in result["indicators"]]
    assert "CRITICAL" in indicator_severities


def test_text_analyzer_lottery_scam():
    result = analyze_text("Congratulations! You won $10,000 cash prize. Claim reward here: https://bit.ly/prize")
    assert result["score"] >= 30
    indicator_names = [i["name"] for i in result["indicators"]]
    assert any("Prize" in name for name in indicator_names)
    assert any("Embedded Link" in name for name in indicator_names)


def test_email_analyzer_benign():
    result = analyze_email(
        sender="colleague@company.com",
        subject="Sprint Planning Notes",
        body="Attached are the notes from today's sprint planning session.",
    )
    assert result["score"] == 0
    assert len(result["indicators"]) == 0


def test_email_analyzer_dangerous_attachment_and_spoof():
    result = analyze_email(
        sender="PayPal Support <service@freemail-fake.com>",
        subject="Urgent: Invoice Overdue - Wire payment requested",
        body="Please open the attached payment slip immediately.",
        attachments=["Invoice_Overdue.pdf.exe"],
    )
    assert result["score"] >= 70
    severities = [i["severity"] for i in result["indicators"]]
    assert "CRITICAL" in severities
    indicator_names = [i["name"] for i in result["indicators"]]
    assert any("Attachment" in name for name in indicator_names)
    assert any("Brand Impersonation" in name for name in indicator_names)


def test_phone_analyzer_benign():
    result = analyze_phone("+14155552671")
    assert result["score"] == 0
    assert len(result["indicators"]) == 0


def test_phone_analyzer_wangiri_fraud():
    # Sierra Leone +232 prefix
    result = analyze_phone("+23276123456")
    assert result["score"] >= 40
    severities = [i["severity"] for i in result["indicators"]]
    assert "CRITICAL" in severities
    assert any("Sierra Leone" in i["name"] for i in result["indicators"])


def test_phone_analyzer_spoofed_digits():
    result = analyze_phone("9999999999")
    assert result["score"] >= 30
    assert any("Spoofed" in i["name"] for i in result["indicators"])


def test_apk_analyzer_benign():
    result = analyze_apk(
        package_name="org.mozilla.firefox",
        permissions=["android.permission.INTERNET", "android.permission.ACCESS_NETWORK_STATE"],
        app_name="Firefox Browser",
    )
    assert result["score"] == 0
    assert len(result["indicators"]) == 0


def test_apk_analyzer_trojan_signature():
    # Banking trojan signature: Accessibility + Overlay + SMS
    result = analyze_apk(
        package_name="com.google.android.update.security",
        permissions=[
            "android.permission.BIND_ACCESSIBILITY_SERVICE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.INTERNET",
            "android.permission.REQUEST_INSTALL_PACKAGES",
        ],
        app_name="Google Play Update Service",
    )
    assert result["score"] >= 80
    indicator_names = [i["name"] for i in result["indicators"]]
    assert any("Banking Trojan Signature" in name for name in indicator_names)
    assert any("OTP Exfiltration" in name for name in indicator_names)
    assert any("Dropper" in name for name in indicator_names)
