"""
ScamBuster Risk Engine — Categories

Defines and correlates threat taxonomy categories based on rule findings
and structural evidence.
"""

from typing import Any, List, Optional, Set
from app.services.url_rule_detector import RuleFinding

# Primary Risk Categories
CATEGORY_POTENTIAL_PHISHING = "potential_phishing"
CATEGORY_SUSPICIOUS_INFRASTRUCTURE = "suspicious_infrastructure"
CATEGORY_CREDENTIAL_HARVESTING = "credential_harvesting"
CATEGORY_DEFENSE_EVASION = "defense_evasion"
CATEGORY_UNENCRYPTED_TRANSPORT = "unencrypted_transport"
CATEGORY_BENIGN_BASELINE = "benign_baseline"
CATEGORY_INSUFFICIENT_EVIDENCE = "insufficient_evidence"

# Mapping of specific rules to categorized threats
RULE_TO_CATEGORIES = {
    "RULE_IP_HOSTNAME": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_SUSPICIOUS_TLD": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_NON_STANDARD_PORT": [CATEGORY_SUSPICIOUS_INFRASTRUCTURE],
    "RULE_KEYWORD_PATTERN": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_CREDENTIAL_HARVESTING],
    "RULE_KEYWORD_SINGLE": [CATEGORY_POTENTIAL_PHISHING],
    "RULE_EXCESSIVE_SUBDOMAINS": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_DEFENSE_EVASION],
    "RULE_USERINFO_SPOOFING": [CATEGORY_POTENTIAL_PHISHING, CATEGORY_DEFENSE_EVASION],
    "RULE_ENCODED_OBFUSCATION": [CATEGORY_DEFENSE_EVASION],
    "RULE_PATH_REDIRECT": [CATEGORY_DEFENSE_EVASION],
    "RULE_UNENCRYPTED_HTTP": [CATEGORY_UNENCRYPTED_TRANSPORT],
}


def determine_categories(findings: List[RuleFinding]) -> List[str]:
    """
    Determine threat categories from triggered rule findings.
    """
    if not findings:
        return [CATEGORY_BENIGN_BASELINE]

    assigned: Set[str] = set()
    for finding in findings:
        cats = RULE_TO_CATEGORIES.get(finding.rule_id, [])
        for c in cats:
            assigned.add(c)

    if not assigned:
        return [CATEGORY_BENIGN_BASELINE]

    # Deterministic sorting
    priority_order = [
        CATEGORY_POTENTIAL_PHISHING,
        CATEGORY_CREDENTIAL_HARVESTING,
        CATEGORY_SUSPICIOUS_INFRASTRUCTURE,
        CATEGORY_DEFENSE_EVASION,
        CATEGORY_UNENCRYPTED_TRANSPORT,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)


# Message Specific Threat Taxonomy Categories
CATEGORY_POTENTIAL_SCAM = "potential_scam"
CATEGORY_CREDENTIAL_THEFT = "credential_theft"
CATEGORY_SMISHING_LURE = "smishing_lure"
CATEGORY_URGENCY_COERCION = "urgency_coercion"
CATEGORY_FINANCIAL_FRAUD = "financial_fraud"
CATEGORY_ADVANCE_FEE_LOTTERY = "advance_fee_lottery"
CATEGORY_EXTORTION_THREAT = "extortion_threat"

MESSAGE_RULE_TO_CATEGORIES = {
    "RULE_CREDENTIAL_SOLICITATION": [CATEGORY_CREDENTIAL_THEFT, CATEGORY_POTENTIAL_SCAM],
    "RULE_ACCOUNT_VERIFICATION_LURE": [CATEGORY_POTENTIAL_SCAM, CATEGORY_CREDENTIAL_THEFT],
    "RULE_URGENCY_PRESSURE": [CATEGORY_URGENCY_COERCION, CATEGORY_POTENTIAL_SCAM],
    "RULE_THREAT_COERCION": [CATEGORY_EXTORTION_THREAT, CATEGORY_POTENTIAL_SCAM],
    "RULE_UNSOLICITED_REWARD": [CATEGORY_ADVANCE_FEE_LOTTERY, CATEGORY_FINANCIAL_FRAUD],
    "RULE_EMBEDDED_LINK": [CATEGORY_SMISHING_LURE],
    "RULE_HIGH_UPPERCASE": [CATEGORY_POTENTIAL_SCAM],
    "RULE_REPEATED_PUNCTUATION": [CATEGORY_POTENTIAL_SCAM],
    "RULE_SENDER_SHORTCODE": [CATEGORY_POTENTIAL_SCAM],
}


def determine_message_categories(
    findings: List[Any],
    embedded_urls: Optional[List[dict]] = None,
    ml_result: Optional[dict] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> List[str]:
    """
    Determine threat categories for an analyzed SMS / text message.
    """
    assigned: Set[str] = set()

    for f in findings:
        rule_id = getattr(f, "rule_id", "")
        cats = MESSAGE_RULE_TO_CATEGORIES.get(rule_id, [])
        for c in cats:
            assigned.add(c)

    if social_engineering_findings:
        for se in social_engineering_findings:
            cat = getattr(se, "category", None)
            if cat:
                cat_val = cat.value.lower() if hasattr(cat, "value") else str(cat).lower()
                assigned.add(cat_val)

    if embedded_urls:
        has_suspicious_url = any(u.get("risk_score", 0) >= 40 for u in embedded_urls)
        if has_suspicious_url:
            assigned.add(CATEGORY_SMISHING_LURE)
            assigned.add(CATEGORY_POTENTIAL_SCAM)

    if ml_result and ml_result.get("prediction") == "scam":
        assigned.add(CATEGORY_POTENTIAL_SCAM)

    if not assigned:
        return [CATEGORY_BENIGN_BASELINE]

    priority_order = [
        "otp_scam",
        CATEGORY_CREDENTIAL_THEFT,
        "account_takeover",
        CATEGORY_SMISHING_LURE,
        CATEGORY_POTENTIAL_SCAM,
        "impersonation",
        "banking_scam",
        "tech_support_scam",
        "investment_scam",
        "job_scam",
        "delivery_scam",
        "malicious_download",
        "malicious_link",
        CATEGORY_EXTORTION_THREAT,
        "fear",
        CATEGORY_FINANCIAL_FRAUD,
        "payment_request",
        CATEGORY_ADVANCE_FEE_LOTTERY,
        "reward",
        CATEGORY_URGENCY_COERCION,
        "urgency",
        CATEGORY_BENIGN_BASELINE,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)


# Email Specific Threat Taxonomy Categories
CATEGORY_EMAIL_SPOOFING = "email_spoofing"
CATEGORY_DECEPTIVE_HYPERLINKS = "deceptive_hyperlinks"
CATEGORY_MALICIOUS_ATTACHMENT = "malicious_attachment"

EMAIL_RULE_TO_CATEGORIES = {
    "RULE_EMAIL_SENDER_REPLYTO_MISMATCH": [CATEGORY_EMAIL_SPOOFING, CATEGORY_POTENTIAL_PHISHING],
    "RULE_EMAIL_AUTH_FAILURE": [CATEGORY_EMAIL_SPOOFING, CATEGORY_DEFENSE_EVASION],
    "RULE_EMAIL_ANCHOR_MISMATCH": [CATEGORY_DECEPTIVE_HYPERLINKS, CATEGORY_POTENTIAL_PHISHING],
    "RULE_EMAIL_DOUBLE_EXTENSION_ATTACHMENT": [CATEGORY_MALICIOUS_ATTACHMENT, CATEGORY_DEFENSE_EVASION],
    "RULE_EMAIL_SUSPICIOUS_ATTACHMENT": [CATEGORY_MALICIOUS_ATTACHMENT],
    "RULE_EMAIL_CREDENTIAL_SOLICITATION": [CATEGORY_CREDENTIAL_HARVESTING, CATEGORY_POTENTIAL_PHISHING],
    "RULE_EMAIL_URGENCY_THREAT": [CATEGORY_URGENCY_COERCION, CATEGORY_POTENTIAL_PHISHING],
    "RULE_EMAIL_FINANCIAL_LURE": [CATEGORY_FINANCIAL_FRAUD],
    "RULE_EMAIL_HTML_FORM": [CATEGORY_CREDENTIAL_HARVESTING, CATEGORY_POTENTIAL_PHISHING],
}


def determine_email_categories(
    findings: List[Any],
    embedded_urls: Optional[List[dict]] = None,
    ml_result: Optional[dict] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> List[str]:
    """
    Determine threat taxonomy categories for an analyzed email message.
    """
    assigned: Set[str] = set()

    for f in findings:
        rule_id = getattr(f, "rule_id", "")
        cats = EMAIL_RULE_TO_CATEGORIES.get(rule_id, [])
        for c in cats:
            assigned.add(c)

    if social_engineering_findings:
        for se in social_engineering_findings:
            cat = getattr(se, "category", None)
            if cat:
                cat_val = cat.value.lower() if hasattr(cat, "value") else str(cat).lower()
                assigned.add(cat_val)

    if embedded_urls:
        has_suspicious_url = any(u.get("risk_score", 0) >= 40 for u in embedded_urls)
        if has_suspicious_url:
            assigned.add(CATEGORY_POTENTIAL_PHISHING)
            assigned.add(CATEGORY_DECEPTIVE_HYPERLINKS)

    if ml_result and ml_result.get("prediction") == "phishing":
        assigned.add(CATEGORY_POTENTIAL_PHISHING)

    if not assigned:
        return [CATEGORY_BENIGN_BASELINE]

    priority_order = [
        "otp_scam",
        "credential_theft",
        CATEGORY_POTENTIAL_PHISHING,
        CATEGORY_CREDENTIAL_HARVESTING,
        "account_takeover",
        CATEGORY_DECEPTIVE_HYPERLINKS,
        "malicious_link",
        CATEGORY_MALICIOUS_ATTACHMENT,
        "malicious_download",
        CATEGORY_EMAIL_SPOOFING,
        "impersonation",
        "banking_scam",
        "tech_support_scam",
        "investment_scam",
        "job_scam",
        "delivery_scam",
        CATEGORY_FINANCIAL_FRAUD,
        "payment_request",
        "reward",
        CATEGORY_DEFENSE_EVASION,
        CATEGORY_URGENCY_COERCION,
        "fear",
        "urgency",
        CATEGORY_BENIGN_BASELINE,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)


# Phone Specific Threat Taxonomy Categories
CATEGORY_POTENTIAL_PHONE_SCAM = "potential_phone_scam"
CATEGORY_WANGIRI_FRAUD = "wangiri_toll_fraud"
CATEGORY_ROBOCALL_SPAM = "robocall_telemarketing_spam"
CATEGORY_AUTHORITY_IMPERSONATION = "authority_impersonation"
CATEGORY_UNVERIFIED_CALLER = "unverified_caller"

PHONE_RULE_TO_CATEGORIES = {
    "PHONE_RULE_INVALID_STRUCTURE": [CATEGORY_UNVERIFIED_CALLER],
    "PHONE_RULE_PREMIUM_RATE": [CATEGORY_WANGIRI_FRAUD, CATEGORY_POTENTIAL_PHONE_SCAM],
    "PHONE_RULE_REPEATED_DIGITS": [CATEGORY_UNVERIFIED_CALLER],
    "PHONE_RULE_SEQUENTIAL_DIGITS": [CATEGORY_UNVERIFIED_CALLER],
    "PHONE_RULE_REGION_MISMATCH": [CATEGORY_UNVERIFIED_CALLER],
    "PHONE_RULE_CONTEXT_IMPERSONATION": [CATEGORY_AUTHORITY_IMPERSONATION, CATEGORY_POTENTIAL_PHONE_SCAM],
    "PHONE_RULE_INTEL_REPORTED_SCAM": [CATEGORY_POTENTIAL_PHONE_SCAM, CATEGORY_ROBOCALL_SPAM],
    "PHONE_RULE_INTEL_SUSPICIOUS": [CATEGORY_POTENTIAL_PHONE_SCAM],
}


def determine_phone_categories(
    findings: List[Any],
    ml_result: Optional[dict] = None,
    intel_result: Optional[Any] = None,
) -> List[str]:
    """
    Determine threat taxonomy categories for an analyzed phone number.
    """
    assigned: Set[str] = set()

    for f in findings:
        rule_id = getattr(f, "rule_id", "")
        cats = PHONE_RULE_TO_CATEGORIES.get(rule_id, [])
        for c in cats:
            assigned.add(c)

    if intel_result:
        rep = getattr(intel_result, "reputation", "unknown")
        if rep == "reported_scam":
            assigned.add(CATEGORY_POTENTIAL_PHONE_SCAM)
        elif rep == "suspicious":
            assigned.add(CATEGORY_UNVERIFIED_CALLER)

    if ml_result and ml_result.get("prediction") == "scam":
        assigned.add(CATEGORY_POTENTIAL_PHONE_SCAM)

    if not assigned:
        return [CATEGORY_UNVERIFIED_CALLER]

    priority_order = [
        CATEGORY_POTENTIAL_PHONE_SCAM,
        CATEGORY_WANGIRI_FRAUD,
        CATEGORY_AUTHORITY_IMPERSONATION,
        CATEGORY_ROBOCALL_SPAM,
        CATEGORY_UNVERIFIED_CALLER,
        CATEGORY_BENIGN_BASELINE,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)


# APK Specific Threat Taxonomy Categories
CATEGORY_BANKING_TROJAN = "banking_trojan"
CATEGORY_SPYWARE = "spyware_surveillance"
CATEGORY_OVERLAY_ABUSE = "overlay_interception"
CATEGORY_SMS_FRAUD = "sms_toll_fraud"
CATEGORY_MALWARE_DROPPER = "malware_dropper"
CATEGORY_POTENTIAL_MALWARE = "potential_malware"
CATEGORY_PRIVACY_RISK = "privacy_risk"
CATEGORY_EXCESSIVE_PERMISSIONS = "excessive_permissions"
CATEGORY_CONTEXT_MISMATCH = "context_mismatch"

APK_RULE_TO_CATEGORIES = {
    "APK_CLUSTER_BANKING_OVERLAY": [CATEGORY_BANKING_TROJAN, CATEGORY_OVERLAY_ABUSE, CATEGORY_POTENTIAL_MALWARE],
    "APK_CLUSTER_OVERLAY_SMS": [CATEGORY_OVERLAY_ABUSE, CATEGORY_BANKING_TROJAN],
    "APK_CLUSTER_SURVEILLANCE": [CATEGORY_SPYWARE, CATEGORY_POTENTIAL_MALWARE],
    "APK_CLUSTER_DROPPER": [CATEGORY_MALWARE_DROPPER, CATEGORY_POTENTIAL_MALWARE],
    "APK_CLUSTER_DEVICE_ADMIN": [CATEGORY_POTENTIAL_MALWARE],
    "APK_CLUSTER_SMS_AUTOSTART": [CATEGORY_SMS_FRAUD],
    "APK_RULE_EXCESSIVE_DANGEROUS_PERMS": [CATEGORY_POTENTIAL_MALWARE],
    "APK_RULE_DYNAMIC_CODE_LOADING": [CATEGORY_MALWARE_DROPPER, CATEGORY_POTENTIAL_MALWARE],
    "APK_RULE_SHELL_EXECUTION": [CATEGORY_POTENTIAL_MALWARE],
    "APK_RULE_SUSPICIOUS_EMBEDDED_URL": [CATEGORY_POTENTIAL_MALWARE],
    "APK_RULE_DEBUG_CERTIFICATE": [CATEGORY_POTENTIAL_MALWARE],
    "APK_RULE_INTEL_MALWARE_MATCH": [CATEGORY_POTENTIAL_MALWARE],
}


def determine_apk_categories(
    findings: List[Any],
    ml_result: Optional[dict] = None,
    intel_result: Optional[Any] = None,
    privacy_result: Optional[Any] = None,
) -> List[str]:
    """
    Determine threat and privacy taxonomy categories for an analyzed Android APK package.
    """
    assigned: Set[str] = set()

    for f in findings:
        rule_id = getattr(f, "rule_id", "")
        cats = APK_RULE_TO_CATEGORIES.get(rule_id, [])
        for c in cats:
            assigned.add(c)

    if intel_result:
        rep = getattr(intel_result, "reputation", "unknown")
        if rep == "known_malware":
            assigned.add(CATEGORY_POTENTIAL_MALWARE)
            fam = getattr(intel_result, "malware_family", "")
            if fam and "trojan" in fam.lower():
                assigned.add(CATEGORY_BANKING_TROJAN)

    if ml_result and ml_result.get("prediction") == "malware":
        assigned.add(CATEGORY_POTENTIAL_MALWARE)

    if privacy_result:
        priv_score = getattr(privacy_result, "privacy_score", 0)
        sens_count = getattr(privacy_result, "sensitive_permissions_count", 0)
        ctx = getattr(privacy_result, "context_analysis", {})
        mismatch = ctx.get("mismatch_level", "NONE") if isinstance(ctx, dict) else getattr(ctx, "mismatch_level", "NONE")

        if priv_score >= 50:
            assigned.add(CATEGORY_PRIVACY_RISK)
        if mismatch in ("HIGH", "MEDIUM"):
            assigned.add(CATEGORY_CONTEXT_MISMATCH)
        if sens_count >= 6:
            assigned.add(CATEGORY_EXCESSIVE_PERMISSIONS)

    if not assigned:
        return [CATEGORY_BENIGN_BASELINE]

    priority_order = [
        CATEGORY_BANKING_TROJAN,
        CATEGORY_POTENTIAL_MALWARE,
        CATEGORY_SPYWARE,
        CATEGORY_OVERLAY_ABUSE,
        CATEGORY_MALWARE_DROPPER,
        CATEGORY_SMS_FRAUD,
        CATEGORY_PRIVACY_RISK,
        CATEGORY_CONTEXT_MISMATCH,
        CATEGORY_EXCESSIVE_PERMISSIONS,
        CATEGORY_BENIGN_BASELINE,
    ]
    return sorted(list(assigned), key=lambda x: priority_order.index(x) if x in priority_order else 99)




