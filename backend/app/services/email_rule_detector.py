"""
ScamBuster Email Rule Detector (Phase 05)

Executes deterministic, rule-based cybersecurity analysis on emails to detect:
- Sender vs. Reply-To Domain divergence (spoofing indicator)
- Authentication failures explicitly reported in mail headers (SPF / DKIM / DMARC)
- Visual Anchor Text vs. Actual Destination URL mismatch (deceptive hyperlinks)
- Executable, script, or double-extension attachment risks
- Credential and verification solicitation
- Artificial urgency and suspension coercion threats
- Advance-fee, inheritance, and lottery financial lures
- Embedded HTML interactive forms / credential capture forms

IMPORTANT:
Rules provide objective evidence indicators. They do not claim absolute proof of fraud.
Missing authentication headers are NOT marked as failures, as email server configurations vary.
"""

from dataclasses import dataclass
import re
from typing import List, Optional
from pydantic import BaseModel

from app.services.email_feature_extractor import EmailFeatures
from app.services.email_parser import ParsedEmail
from app.services.email_preprocessor import PreprocessedEmailData


class EmailRuleFinding(BaseModel):
    """Structured email rule detection finding."""
    rule_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    score_weight: int
    description: str
    evidence: str


def evaluate_email_rules(
    preprocessed: PreprocessedEmailData,
    features: EmailFeatures,
) -> List[EmailRuleFinding]:
    """
    Evaluate deterministic cybersecurity rules against preprocessed email and features.
    """
    findings: List[EmailRuleFinding] = []
    parsed = preprocessed.parsed_email
    body_lower = preprocessed.clean_body_text.lower()
    subject_lower = preprocessed.clean_subject_text.lower()

    # 1. Rule: Sender vs Reply-To Mismatch (HIGH)
    if preprocessed.has_sender_replyto_mismatch:
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_SENDER_REPLYTO_MISMATCH",
                name="Sender and Reply-To Domain Divergence",
                severity="HIGH",
                score_weight=30,
                description="The Return/Reply-To domain differs from the claimed From sender domain, frequently used in address spoofing to divert responses.",
                evidence=preprocessed.domain_mismatch_reason or f"From: {parsed.sender_domain} | Reply-To: {parsed.reply_to_domain}",
            )
        )

    # 2. Rule: Mail Authentication Failure (HIGH)
    auth = parsed.auth_results
    failed_mechanisms = []
    if auth.spf_status in ["fail", "softfail"]:
        failed_mechanisms.append(f"SPF ({auth.spf_status})")
    if auth.dkim_status == "fail":
        failed_mechanisms.append(f"DKIM ({auth.dkim_status})")
    if auth.dmarc_status == "fail":
        failed_mechanisms.append(f"DMARC ({auth.dmarc_status})")

    if failed_mechanisms:
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_AUTH_FAILURE",
                name="Explicit Mail Authentication Failure",
                severity="HIGH",
                score_weight=35,
                description="Headers explicitly record authentication check failures, indicating the sending mail transfer agent failed cryptographic or policy validation.",
                evidence=f"Failed checks: {', '.join(failed_mechanisms)}",
            )
        )

    # 3. Rule: Anchor Text vs Destination Mismatch (CRITICAL)
    if preprocessed.anchor_mismatches:
        mismatch_count = len(preprocessed.anchor_mismatches)
        first_mismatch = preprocessed.anchor_mismatches[0]
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_ANCHOR_MISMATCH",
                name="Deceptive Hyperlink (Anchor Text / Destination Mismatch)",
                severity="CRITICAL",
                score_weight=40,
                description="Hyperlink visually displays a legitimate brand or trusted web address, but the actual destination directs the victim to a divergent host.",
                evidence=f"{mismatch_count} deceptive link(s) detected. Example: {first_mismatch.mismatch_details}",
            )
        )

    # 4. Rule: Dangerous / Suspicious Attachment Metadata (CRITICAL / HIGH)
    if features.double_extension_count > 0:
        double_exts = [a.filename for a in parsed.attachments if a.is_double_extension]
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_DOUBLE_EXTENSION_ATTACHMENT",
                name="Double-Extension Attachment Signature",
                severity="CRITICAL",
                score_weight=40,
                description="Attachment uses a deceptive double file extension (e.g. .pdf.exe) designed to masquerade an executable binary as a benign document.",
                evidence=f"Suspicious files: {', '.join(double_exts[:3])}",
            )
        )
    elif features.suspicious_attachment_count > 0:
        susp_exts = [f"{a.filename} ({a.extension})" for a in parsed.attachments if a.is_suspicious_extension]
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_SUSPICIOUS_ATTACHMENT",
                name="High-Risk Attachment Type Detected",
                severity="HIGH",
                score_weight=35,
                description="Attachment contains an executable, script, or disk image format commonly leveraged for malware delivery.",
                evidence=f"Detected: {', '.join(susp_exts[:3])}",
            )
        )

    # 5. Rule: Credential & Account Verification Request (HIGH)
    if features.credential_keyword_count > 0:
        cred_matches = re.findall(
            r"\b(password|passcode|login|verify account|verification code|billing info|credentials|confirm identity|update details)\b",
            f"{subject_lower} {body_lower}"
        )
        if cred_matches:
            evidence_str = ", ".join(set(cred_matches[:3]))
            findings.append(
                EmailRuleFinding(
                    rule_id="RULE_EMAIL_CREDENTIAL_SOLICITATION",
                    name="Account Verification or Credential Solicitation",
                    severity="HIGH",
                    score_weight=25,
                    description="Message solicits sensitive login credentials, account passwords, or personal identity verification.",
                    evidence=f"Detected credential solicitation keywords: [{evidence_str}]",
                )
            )

    # 6. Rule: Artificial Urgency & Coercion (MEDIUM)
    if features.urgency_keyword_count >= 2 or any(k in subject_lower for k in ["urgent", "immediate", "suspended", "action required", "terminate"]):
        urg_matches = re.findall(
            r"\b(urgent|immediately|act now|suspended|suspension|locked|terminate|24 hours|action required)\b",
            f"{subject_lower} {body_lower}"
        )
        if urg_matches:
            findings.append(
                EmailRuleFinding(
                    rule_id="RULE_EMAIL_URGENCY_THREAT",
                    name="High-Pressure Urgency & Coercion Indicators",
                    severity="MEDIUM",
                    score_weight=20,
                    description="Message employs psychological urgency cues or immediate punitive threats to rush user decision-making.",
                    evidence=f"Urgency indicators: [{', '.join(set(urg_matches[:3]))}]",
                )
            )

    # 7. Rule: Financial Lure or Advance-Fee Fraud (MEDIUM)
    if features.financial_keyword_count >= 2:
        fin_matches = re.findall(
            r"\b(wire transfer|lottery|prize|inheritance|payout|unclaimed funds|bitcoin|crypto|million)\b",
            body_lower
        )
        if fin_matches:
            findings.append(
                EmailRuleFinding(
                    rule_id="RULE_EMAIL_FINANCIAL_LURE",
                    name="Advance-Fee or Unsolicited Financial Lure",
                    severity="MEDIUM",
                    score_weight=20,
                    description="Email promises unsolicited financial payouts, lottery winnings, or high-value transfers characteristic of advance-fee scams.",
                    evidence=f"Financial keywords: [{', '.join(set(fin_matches[:3]))}]",
                )
            )

    # 8. Rule: Embedded HTML Form (HIGH)
    if features.html_form_count > 0:
        findings.append(
            EmailRuleFinding(
                rule_id="RULE_EMAIL_HTML_FORM",
                name="Embedded Interactive HTML Form",
                severity="HIGH",
                score_weight=25,
                description="Email body contains embedded HTML form elements, which are frequently used by phishing lures to capture credentials directly inside email clients.",
                evidence=f"Detected {features.html_form_count} HTML form(s) and {features.html_hidden_element_count} hidden input element(s).",
            )
        )

    return findings
