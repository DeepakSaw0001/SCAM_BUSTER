"""
ScamBuster — Social Engineering Rules Engine (Phase 10)

Evaluates psychological manipulation, deception, and structural attack vectors:
1. Urgency Manipulation (artificial deadlines, countdown pressure)
2. Fear, Intimidation & Coercion (arrest, lawsuits, police, account closure)
3. Reward & Prize Lures (lottery, windfall, unsolicited grants, crypto doubling)
4. Credential Harvesting (passwords, PINs, CVVs, login forms)
5. OTP / Verification Code Solicitation (with mandatory educational warning)
6. Unsolicited Payment & Advance-Fee Requests (UPI, wire, gift cards, crypto ATM)
7. Brand Impersonation & Lookalike Domains (display name vs domain, link destination)
8. Hidden Anchor Text Mismatch (visible text vs actual destination)
9. Dangerous & Executable Attachments (APK, EXE, scripts, macros, zip bombs)
10. Phone Number & Caller Fraud Correlation (Wangiri, tech support lures, shortcodes)

Rules return structured evidence conforming to the Social Engineering Taxonomy,
including analytical severity, confidence, evidence source, and educational guidance.
"""

from dataclasses import dataclass, field
import hashlib
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from app.security.social_engineering.taxonomy import (
    SocialEngineeringCategory,
    get_category_metadata,
)
from app.intelligence.brands.lookalike_detector import (
    BrandMismatchFinding,
    detect_brand_domain_mismatches,
)


@dataclass
class SocialEngineeringFinding:
    rule_id: str
    name: str
    category: SocialEngineeringCategory
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence: float  # 0.0 - 1.0
    evidence: str
    source: str  # e.g. "NLP Rules", "Header Analysis", "Brand Intelligence", "Anchor Verification"
    score_weight: int
    why_it_matters: str
    safe_recommendations: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category.value,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "source": self.source,
            "score_weight": self.score_weight,
            "why_it_matters": self.why_it_matters,
            "safe_recommendations": self.safe_recommendations,
        }


# High-risk executable & script attachment extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".hta", ".cpl", ".jar", ".iso", ".img", ".pif", ".msi", ".reg",
    ".dll", ".sys", ".com", ".gadget", ".vbe", ".jse"
}

# Macro-enabled office document extensions
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# Mobile application package
MOBILE_PACKAGE_EXTENSIONS = {".apk", ".aab", ".xapk", ".apks"}

# Compressed archives
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}

# Double-extension pattern (e.g. invoice.pdf.exe)
DOUBLE_EXT_PATTERN = re.compile(
    r"\.[a-zA-Z0-9]{2,5}\.(exe|scr|bat|cmd|ps1|vbs|js|hta|msi|pif|apk)$",
    re.IGNORECASE
)


# NLP Pattern Registries
URGENCY_PATTERNS = [
    (r"\b(within\s+\d+\s+(?:hours?|minutes?|days?)|today\s+only|last\s+warning|final\s+notice)\b", "Artificial Deadline / Countdown"),
    (r"\b(act\s+immediately|immediate\s+action\s+required|right\s+away|without\s+delay|urgent(?:ly)?|asap)\b", "Urgent Compliance Demand"),
    (r"\b(?:account|access)\s+(?:has\s+been|is|will\s+be)?\s*(?:suspended|closed|terminated|deactivated|locked)\b", "Threat of Account Suspension"),
    (r"\b(access\s+(?:restricted|blocked|frozen)|pending\s+cancellation)\b", "Account Disruption Notification"),
]

FEAR_PATTERNS = [
    (r"\b(legal\s+action|lawsuit|prosecution|arrest\s+warrant|court\s+summons)\b", "Law Enforcement / Legal Action Threat"),
    (r"\b(police|fbi|interpol|cbi|tax\s+evasion\s+penalty|criminal\s+charges)\b", "Intimidation Coercion"),
    (r"\b(security\s+violation|severe\s+penalty|warrant\s+issued|confiscation)\b", "Sanction Threat"),
]

REWARD_PATTERNS = [
    (r"\b(you(?:'ve|\s+have)?\s+won|lucky\s+winner|prize\s+money|lottery\s+winner|jackpot)\b", "Lottery / Prize Win Claim"),
    (r"\b(claim\s+(?:your\s+)?(?:reward|prize|cash|gift|bonus|payout|grant|airdrop))\b", "Unsolicited Reward Claim Bait"),
    (r"\b(free\s+(?:gift\s+card|iphone|voucher|crypto)|100%\s+guaranteed\s+payout)\b", "High-Value Promotional Lure"),
    (r"\b(double\s+your\s+(?:money|crypto|bitcoin)|guaranteed\s+(?:return|profit))\b", "High-Yield Investment Fraud Pattern"),
]

CREDENTIAL_PATTERNS = [
    (r"\b(enter|provide|type|submit)\s+(?:your\s+)?(?:password|pin|passcode|security\s+answer|credentials|login\s+details)\b", "Direct Password / PIN Solicitation"),
    (r"\b(verify|confirm|validate|update|reset)\s+(?:your\s+)?(?:identity|password|passcode|pin|banking\s+details|ssn|card\s+number|account\s+details)\b", "Credential Verification Lure"),
    (r"\b(card\s+number|cvv|cvc|security\s+code\s+on\s+(?:back|card)|atm\s+pin)\b", "Payment Card / CVV Harvesting"),
    (r"\b(seed\s+phrase|private\s+key|recovery\s+phrase|secret\s+key)\b", "Cryptocurrency Seed Phrase Solicitation"),
    (r"\b(update\s+(?:billing|kyc|pan\s+card|aadhaar|ssn)\s+immediately)\b", "Mandatory Identity / KYC Lure"),
]

OTP_PATTERNS = [
    (r"\b(?:share|send|tell|give|provide|forward)\s+(?:me|us)?\s*(?:the|your)?\s*(?:otp|code|verification\s+code|one[- ]time\s+password)\b", "Direct OTP Extraction Request"),
    (r"\b(forward\s+(?:the\s+)?(?:sms|code|otp)|tell\s+(?:me|support)\s+(?:the\s+)?(?:code|otp))\b", "OTP Forwarding Demand"),
    (r"\b(disclose\s+(?:the\s+)?(?:code|otp)|enter\s+(?:the\s+)?(?:code|otp)\s+to\s+cancel\s+transaction)\b", "Transaction Reversal OTP Trick"),
]

PAYMENT_PATTERNS = [
    (r"\b(advance\s+fee|processing\s+fee|customs\s+(?:duty|tax|clearance\s+fee)|handling\s+charge)\b", "Advance / Processing Fee Scam Pattern"),
    (r"\b(pay\s+(?:via\s+)?(?:gift\s+cards?|crypto|bitcoin|wire\s+transfer|western\s+union))\b", "Irreversible Payment Rail Solicitation"),
    (r"\b(send\s+money\s+first|deposit\s+fee\s+to\s+release|refund\s+processing\s+fee)\b", "Pre-Refund Deposit Demand"),
]

DELIVERY_PATTERNS = [
    (r"\b(package|parcel|shipment|delivery)\s+(?:is\s+)?(?:held|delayed|failed|undeliverable|pending\s+address)\b", "Failed / Delayed Delivery Alert"),
    (r"\b(update\s+(?:your\s+)?(?:delivery\s+)?address\s+to\s+receive|reschedule\s+delivery)\b", "Courier Reschedule Lure"),
    (r"\b(customs\s+fee\s+required|small\s+redelivery\s+charge)\b", "Delivery Surcharge Bait"),
]

TECH_SUPPORT_PATTERNS = [
    (r"\b(call\s+(?:us\s+at\s+)?(?:\+?1[-\s]?)?8\d{2}[-\s]?\d{3}[-\s]?\d{4}|call\s+toll-?free|helpline\s+number)\b", "Toll-Free Tech Support Helpline Lure"),
    (r"\b(virus\s+detected|trojan\s+found|computer\s+is\s+infected|critical\s+system\s+alert)\b", "Fabricated Malware Panic"),
    (r"\b(install\s+(?:anydesk|teamviewer|quicksupport|ultraviewer))\b", "Remote Access Tool (RAT) Installation Lure"),
]


def evaluate_social_engineering_rules(
    message_text: str,
    subject: Optional[str] = None,
    sender_display_name: Optional[str] = None,
    sender_domain: Optional[str] = None,
    reply_to_domain: Optional[str] = None,
    extracted_urls: Optional[List[str]] = None,
    anchor_mismatches: Optional[List[Any]] = None,
    attachments: Optional[List[Dict[str, Any]]] = None,
    extracted_phones: Optional[List[str]] = None,
    header_auth: Optional[Dict[str, Any]] = None,
) -> List[SocialEngineeringFinding]:
    """
    Execute complete social engineering inspection combining:
    - NLP manipulation indicators (Urgency, Fear, Reward, Credentials, OTP, Payment)
    - Identity & Sender indicators (Brand impersonation, From/Reply-To mismatch, Auth failure)
    - Structural deception (Hidden link mismatch, Dangerous attachments)
    - Phone number signals
    """
    findings: List[SocialEngineeringFinding] = []
    combined_text = f"{subject or ''}\n{message_text}".strip()
    lower_text = combined_text.lower()

    extracted_urls = extracted_urls or []
    attachments = attachments or []
    extracted_phones = extracted_phones or []
    anchor_mismatches = anchor_mismatches or []

    # -------------------------------------------------------------
    # 1. OTP Solicitations (CRITICAL)
    # -------------------------------------------------------------
    for pat, name in OTP_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.OTP_SCAM)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_OTP_HARVEST",
                    name=name,
                    category=SocialEngineeringCategory.OTP_SCAM,
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence=f"Matched pattern '{m.group(0)}' in message content.",
                    source="NLP Rule Engine",
                    score_weight=45,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 2. Credential Theft / Harvesting (CRITICAL)
    # -------------------------------------------------------------
    for pat, name in CREDENTIAL_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.CREDENTIAL_THEFT)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_CREDENTIAL_HARVEST",
                    name=name,
                    category=SocialEngineeringCategory.CREDENTIAL_THEFT,
                    severity="CRITICAL",
                    confidence=0.90,
                    evidence=f"Matched credential solicitation pattern: '{m.group(0)}'.",
                    source="NLP Rule Engine",
                    score_weight=35,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 3. Urgency Pressure Tactics (MEDIUM)
    # -------------------------------------------------------------
    urgency_hits = []
    for pat, name in URGENCY_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            urgency_hits.append(m.group(0))
    if urgency_hits:
        cat_meta = get_category_metadata(SocialEngineeringCategory.URGENCY)
        findings.append(
            SocialEngineeringFinding(
                rule_id="RULE_SE_URGENCY_MANIPULATION",
                name="Artificial Urgency & Countdown Pressure",
                category=SocialEngineeringCategory.URGENCY,
                severity="MEDIUM",
                confidence=0.85,
                evidence=f"Detected high-pressure urgency triggers: {', '.join(urgency_hits[:2])}.",
                source="NLP Rule Engine",
                score_weight=15,
                why_it_matters=cat_meta.why_it_matters,
                safe_recommendations=cat_meta.safe_recommendations,
            )
        )

    # -------------------------------------------------------------
    # 4. Fear & Intimidation Tactics (HIGH)
    # -------------------------------------------------------------
    fear_hits = []
    for pat, name in FEAR_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            fear_hits.append(m.group(0))
    if fear_hits:
        cat_meta = get_category_metadata(SocialEngineeringCategory.FEAR)
        findings.append(
            SocialEngineeringFinding(
                rule_id="RULE_SE_FEAR_COERCION",
                name="Fear, Intimidation & Coercion Indicators",
                category=SocialEngineeringCategory.FEAR,
                severity="HIGH",
                confidence=0.85,
                evidence=f"Detected intimidation/legal coercion language: {', '.join(fear_hits[:2])}.",
                source="NLP Rule Engine",
                score_weight=25,
                why_it_matters=cat_meta.why_it_matters,
                safe_recommendations=cat_meta.safe_recommendations,
            )
        )

    # -------------------------------------------------------------
    # 5. Reward / Prize / Lottery Lures (HIGH)
    # -------------------------------------------------------------
    for pat, name in REWARD_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.REWARD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_REWARD_BAIT",
                    name=name,
                    category=SocialEngineeringCategory.REWARD,
                    severity="HIGH",
                    confidence=0.88,
                    evidence=f"Detected unsolicited windfall or reward trigger: '{m.group(0)}'.",
                    source="NLP Rule Engine",
                    score_weight=25,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 6. Unsolicited Payment Requests (MEDIUM/HIGH)
    # -------------------------------------------------------------
    for pat, name in PAYMENT_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.PAYMENT_REQUEST)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_PAYMENT_REQUEST",
                    name=name,
                    category=SocialEngineeringCategory.PAYMENT_REQUEST,
                    severity="MEDIUM",
                    confidence=0.85,
                    evidence=f"Detected advance-fee or atypical payment request: '{m.group(0)}'.",
                    source="NLP Rule Engine",
                    score_weight=20,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 7. Delivery & Postal Impersonation (MEDIUM/HIGH)
    # -------------------------------------------------------------
    for pat, name in DELIVERY_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.DELIVERY_SCAM)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_DELIVERY_SCAM",
                    name=name,
                    category=SocialEngineeringCategory.DELIVERY_SCAM,
                    severity="MEDIUM",
                    confidence=0.82,
                    evidence=f"Detected delivery disruption trigger: '{m.group(0)}'.",
                    source="NLP Rule Engine",
                    score_weight=20,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 8. Tech Support & System Virus Bait (HIGH)
    # -------------------------------------------------------------
    for pat, name in TECH_SUPPORT_PATTERNS:
        m = re.search(pat, lower_text)
        if m:
            cat_meta = get_category_metadata(SocialEngineeringCategory.TECH_SUPPORT_SCAM)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_TECH_SUPPORT",
                    name=name,
                    category=SocialEngineeringCategory.TECH_SUPPORT_SCAM,
                    severity="HIGH",
                    confidence=0.88,
                    evidence=f"Detected tech support bait pattern: '{m.group(0)}'.",
                    source="NLP Rule Engine",
                    score_weight=25,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break

    # -------------------------------------------------------------
    # 9. Hidden Anchor Text Mismatch (CRITICAL)
    # -------------------------------------------------------------
    if anchor_mismatches:
        for mis in anchor_mismatches:
            disp = getattr(mis, "displayed_text", None) or mis.get("displayed_text", "")
            actual = getattr(mis, "actual_hostname", None) or getattr(mis, "hostname", None) or mis.get("hostname", "")
            desc = getattr(mis, "mismatch_description", None) or getattr(mis, "mismatch_details", None) or mis.get("mismatch_details", "")
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_LINK)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_ANCHOR_MISMATCH",
                    name="Deceptive Anchor Text Mismatch",
                    category=SocialEngineeringCategory.MALICIOUS_LINK,
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence=desc or f"Anchor text '{disp}' directs to different destination '{actual}'.",
                    source="HTML Content Inspector",
                    score_weight=40,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            break  # Flag primary anchor mismatch finding

    # -------------------------------------------------------------
    # 10. Brand Impersonation & Lookalike Domain Verification
    # -------------------------------------------------------------
    candidate_domains: List[Tuple[str, str]] = []
    if sender_domain:
        candidate_domains.append((sender_domain, "sender_domain"))
    if reply_to_domain:
        candidate_domains.append((reply_to_domain, "reply_to_domain"))
    for u in extracted_urls[:5]:
        try:
            from urllib.parse import urlparse
            h = urlparse(u if u.startswith("http") else "http://" + u).hostname
            if h:
                candidate_domains.append((h, "link_destination"))
        except Exception:
            pass

    brand_mismatches = detect_brand_domain_mismatches(
        claimed_text=combined_text,
        domains=candidate_domains,
        sender_display_name=sender_display_name,
    )
    for bm in brand_mismatches:
        cat_meta = get_category_metadata(SocialEngineeringCategory.IMPERSONATION)
        findings.append(
            SocialEngineeringFinding(
                rule_id="RULE_SE_BRAND_LOOKALIKE" if bm.is_lookalike else "RULE_SE_BRAND_DOMAIN_MISMATCH",
                name=f"Brand Lookalike: {bm.brand.display_name}" if bm.is_lookalike else f"Brand Impersonation: {bm.brand.display_name}",
                category=SocialEngineeringCategory.IMPERSONATION,
                severity=bm.severity,
                confidence=0.92 if bm.is_lookalike else 0.85,
                evidence=bm.description,
                source="Brand Intelligence Layer",
                score_weight=35 if bm.is_lookalike else 25,
                why_it_matters=cat_meta.why_it_matters,
                safe_recommendations=cat_meta.safe_recommendations,
            )
        )

    # -------------------------------------------------------------
    # 11. Sender vs. Reply-To Domain Divergence (MEDIUM)
    # -------------------------------------------------------------
    if sender_domain and reply_to_domain:
        s_d = sender_domain.lower().strip()
        r_d = reply_to_domain.lower().strip()
        if s_d != r_d and not s_d.endswith("." + r_d) and not r_d.endswith("." + s_d):
            cat_meta = get_category_metadata(SocialEngineeringCategory.IMPERSONATION)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_REPLY_TO_DIVERGENCE",
                    name="Mismatched Reply-To Address",
                    category=SocialEngineeringCategory.IMPERSONATION,
                    severity="MEDIUM",
                    confidence=0.85,
                    evidence=f"Sender 'From' domain is '{s_d}', but replies route to '{r_d}'.",
                    source="Header Analysis",
                    score_weight=20,
                    why_it_matters="Phishing attackers often use spoofed sender domains but configure Reply-To to redirect replies to an attacker-controlled inbox.",
                    safe_recommendations=[
                        "Do not use in-email 'Reply' buttons when Reply-To address differs from the sender domain.",
                        "Inspect full email headers to check the true sender trajectory.",
                    ],
                )
            )

    # -------------------------------------------------------------
    # 12. Email Authentication (SPF / DKIM / DMARC) Failures (MEDIUM)
    # -------------------------------------------------------------
    if header_auth and header_auth.get("headers_supplied", False):
        spf = str(header_auth.get("spf", {}).get("status", "")).lower()
        dmarc = str(header_auth.get("dmarc", {}).get("status", "")).lower()
        if spf == "fail" or dmarc == "fail":
            cat_meta = get_category_metadata(SocialEngineeringCategory.IMPERSONATION)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_AUTH_FAILURE",
                    name="Email Authentication Verification Failure",
                    category=SocialEngineeringCategory.IMPERSONATION,
                    severity="MEDIUM",
                    confidence=0.80,
                    evidence=f"Reported authentication check failure: SPF={spf.upper()}, DMARC={dmarc.upper()}.",
                    source="Header Authentication Analyzer",
                    score_weight=20,
                    why_it_matters="Authentication failures indicate the sending mail server was not authorized by the domain owner to transmit emails on its behalf.",
                    safe_recommendations=[
                        "Exercise elevated scrutiny when email authentication headers fail.",
                        "Verify urgent requests via a secondary communication channel.",
                    ],
                )
            )

    # -------------------------------------------------------------
    # 13. Dangerous Attachments (CRITICAL / HIGH)
    # -------------------------------------------------------------
    for att in attachments:
        fn = str(att.get("filename", "")).lower()
        ext = str(att.get("extension", "")).lower()
        size = int(att.get("size_bytes", 0))

        # Check double extension
        if DOUBLE_EXT_PATTERN.search(fn):
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_DOWNLOAD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_DOUBLE_EXTENSION_ATTACHMENT",
                    name="Deceptive Double Extension Attachment",
                    category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence=f"Attachment '{fn}' uses deceptive double extension masking executable payload.",
                    source="Attachment Analysis",
                    score_weight=45,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
            continue

        # Check dangerous executable / script extension
        if ext in DANGEROUS_EXTENSIONS:
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_DOWNLOAD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_DANGEROUS_ATTACHMENT",
                    name="Dangerous / Executable Attachment Detected",
                    category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
                    severity="CRITICAL",
                    confidence=0.95,
                    evidence=f"Attachment '{fn}' has dangerous executable extension '{ext}'.",
                    source="Attachment Analysis",
                    score_weight=45,
                    why_it_matters=cat_meta.why_it_matters,
                    safe_recommendations=cat_meta.safe_recommendations,
                )
            )
        elif ext in MOBILE_PACKAGE_EXTENSIONS:
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_DOWNLOAD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_APK_ATTACHMENT",
                    name="Android APK Package Attachment Detected",
                    category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
                    severity="HIGH",
                    confidence=0.92,
                    evidence=f"Attachment '{fn}' is an Android application package (.apk). Can be routed to Phase 07 APK analyzer.",
                    source="Attachment Analysis",
                    score_weight=35,
                    why_it_matters="Side-loaded APK attachments delivered via email or SMS are primary vectors for mobile banking trojans and spyware.",
                    safe_recommendations=[
                        "Never install APK files received via email, SMS, or chat applications.",
                        "Install applications strictly from official app stores.",
                    ],
                )
            )
        elif ext in MACRO_EXTENSIONS:
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_DOWNLOAD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_MACRO_ATTACHMENT",
                    name="Macro-Enabled Document Attachment",
                    category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
                    severity="HIGH",
                    confidence=0.88,
                    evidence=f"Attachment '{fn}' is a macro-enabled document ({ext}) capable of executing automated VBA code.",
                    source="Attachment Analysis",
                    score_weight=30,
                    why_it_matters="Macro-enabled documents are widely exploited to drop loaders and ransomware when opened.",
                    safe_recommendations=[
                        "Do not enable macros or editing when opening unsolicited documents.",
                    ],
                )
            )
        elif ext in ARCHIVE_EXTENSIONS:
            # Check suspicious compressed archive
            cat_meta = get_category_metadata(SocialEngineeringCategory.MALICIOUS_DOWNLOAD)
            findings.append(
                SocialEngineeringFinding(
                    rule_id="RULE_SE_ARCHIVE_ATTACHMENT",
                    name="Compressed Archive Container Attachment",
                    category=SocialEngineeringCategory.MALICIOUS_DOWNLOAD,
                    severity="LOW",
                    confidence=0.75,
                    evidence=f"Attachment '{fn}' is a compressed container ({ext}). May conceal uninspected payloads.",
                    source="Attachment Analysis",
                    score_weight=15,
                    why_it_matters="Compressed archives are often used to bypass email gateway filters.",
                    safe_recommendations=[
                        "Inspect archive contents with antivirus before extracting.",
                    ],
                )
            )

    return findings
