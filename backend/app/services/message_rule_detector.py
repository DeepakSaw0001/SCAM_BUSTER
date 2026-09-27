"""
ScamBuster Message Rule Detector (Phase 04)

Executes deterministic, rule-based cybersecurity analysis on text messages to detect:
- Credential and verification code harvesting
- High-pressure urgency and artificial countdowns
- Financial lures and advance-fee fraud patterns
- Account suspension and legal coercion threats
- Unsolicited lottery, prize, or airdrop claims
- Embedded link presence (Smishing threat vector)
- Excessive uppercase capitalization (intimidation/shouting)

IMPORTANT:
Rules provide objective evidence indicators. They do not claim absolute proof of fraud.
"""

import re
from typing import List, Optional
from pydantic import BaseModel

from app.services.message_feature_extractor import MessageFeatures
from app.services.message_preprocessor import PreprocessedMessage


class MessageRuleFinding(BaseModel):
    """Structured rule detection finding."""
    rule_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    score_weight: int
    description: str
    evidence: str


def evaluate_message_rules(
    preprocessed: PreprocessedMessage,
    features: MessageFeatures,
    sender: Optional[str] = None
) -> List[MessageRuleFinding]:
    """
    Evaluate deterministic cybersecurity rules against preprocessed message and extracted features.
    """
    findings: List[MessageRuleFinding] = []
    text_lower = preprocessed.normalized_text.lower()
    raw = preprocessed.original_text

    # 1. Rule: Credential & OTP Harvesting (CRITICAL)
    if features.credential_terms_count > 0:
        # Check specific credential patterns
        cred_matches = re.findall(
            r"\b(otp|one[- ]time password|verification code|security code|passcode|enter your pin|cvv|password|seed phrase)\b",
            text_lower
        )
        if cred_matches:
            evidence_str = ", ".join(set(cred_matches[:3]))
            findings.append(MessageRuleFinding(
                rule_id="RULE_CREDENTIAL_SOLICITATION",
                name="Credential or Verification Code Request",
                severity="CRITICAL",
                score_weight=35,
                description="The message requests confidential security credentials, passwords, or one-time verification tokens.",
                evidence=f"Matched term(s): {evidence_str}",
            ))
        elif "verify" in text_lower or "account" in text_lower:
            findings.append(MessageRuleFinding(
                rule_id="RULE_ACCOUNT_VERIFICATION_LURE",
                name="Account Verification Lure",
                severity="HIGH",
                score_weight=25,
                description="The message instructs the recipient to verify or update account details under potential pretense.",
                evidence="Account verification language detected",
            ))

    # 2. Rule: Artificial Urgency & Coercion (HIGH)
    if features.urgency_terms_count > 0:
        urg_matches = re.findall(
            r"\b(immediately|act now|urgent|right away|expires|hurry|within 24 hours|within 12 hours|today only)\b",
            text_lower
        )
        if urg_matches:
            evidence_str = ", ".join(set(urg_matches[:3]))
            findings.append(MessageRuleFinding(
                rule_id="RULE_URGENCY_PRESSURE",
                name="High-Pressure Urgency Coercion",
                severity="HIGH",
                score_weight=20,
                description="High-pressure psychological manipulation designed to induce panic and hasty compliance.",
                evidence=f"Matched term(s): {evidence_str}",
            ))

    # 3. Rule: Account Disruption or Legal Threat (HIGH)
    if features.threat_terms_count > 0:
        threat_matches = re.findall(
            r"\b(suspended|terminated|disabled|locked|restricted|legal action|arrest|lawsuit|investigation|frozen)\b",
            text_lower
        )
        if threat_matches:
            evidence_str = ", ".join(set(threat_matches[:3]))
            findings.append(MessageRuleFinding(
                rule_id="RULE_THREAT_COERCION",
                name="Account Suspension or Legal Threat",
                severity="HIGH",
                score_weight=25,
                description="Intimidation language threatening negative consequences, service termination, or legal penalties.",
                evidence=f"Matched term(s): {evidence_str}",
            ))

    # 4. Rule: Unsolicited Lottery / Prize Reward Bait (MEDIUM)
    if features.reward_terms_count > 0:
        reward_matches = re.findall(
            r"\b(winner|won|prize|free|claim|jackpot|lottery|voucher|gift card|congratulations)\b",
            text_lower
        )
        if reward_matches:
            evidence_str = ", ".join(set(reward_matches[:3]))
            findings.append(MessageRuleFinding(
                rule_id="RULE_UNSOLICITED_REWARD",
                name="Unsolicited Prize or Reward Claim",
                severity="MEDIUM",
                score_weight=20,
                description="Promises of unexpected monetary rewards, lottery winnings, or free vouchers typical of advance-fee scams.",
                evidence=f"Matched term(s): {evidence_str}",
            ))

    # 5. Rule: Embedded URL / Smishing Vector (MEDIUM)
    if features.has_url:
        evidence_str = ", ".join(preprocessed.extracted_urls[:2])
        findings.append(MessageRuleFinding(
            rule_id="RULE_EMBEDDED_LINK",
            name="Embedded Hyperlink in Message",
            severity="MEDIUM",
            score_weight=15,
            description="Direct link embedded in text message posing potential smishing or drive-by redirection threat.",
            evidence=f"Link(s): {evidence_str}",
        ))

    # 6. Rule: Excessive Uppercase Capitalization (LOW)
    if features.uppercase_ratio > 0.40 and features.message_length > 20:
        findings.append(MessageRuleFinding(
            rule_id="RULE_HIGH_UPPERCASE",
            name="Excessive Capitalization Formatting",
            severity="LOW",
            score_weight=10,
            description="Abnormally high proportion of uppercase characters used to simulate shouting or alarm.",
            evidence=f"Uppercase ratio: {int(features.uppercase_ratio * 100)}%",
        ))

    # 7. Rule: Multiple Exclamation Punctuation (LOW)
    if features.exclamation_count >= 3:
        findings.append(MessageRuleFinding(
            rule_id="RULE_REPEATED_PUNCTUATION",
            name="Excessive Punctuation Urgency",
            severity="LOW",
            score_weight=5,
            description="Repeated exclamation marks often accompanying sensationalized spam lures.",
            evidence=f"Exclamation marks: {features.exclamation_count}",
        ))

    # 8. Sender check if provided
    if sender:
        clean_sender = sender.strip()
        if re.search(r"^\+?[0-9]{3,6}$", clean_sender):
            findings.append(MessageRuleFinding(
                rule_id="RULE_SENDER_SHORTCODE",
                name="Unregistered Numeric Shortcode",
                severity="LOW",
                score_weight=5,
                description="Message originates from an unverified numeric shortcode identifier.",
                evidence=f"Sender: {clean_sender}",
            ))

    return findings
