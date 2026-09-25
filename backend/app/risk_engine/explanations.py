"""
ScamBuster Risk Engine — Explanations & Actionable Guidance

Generates human-readable, evidence-based explanations and defensive recommendations.

Key Principles:
- Describes concrete evidence neutrally.
- Never falsely claims "This proves the website is malicious."
- Provides clear, actionable defensive recommendations.
"""

from typing import List
from app.services.url_rule_detector import RuleFinding


def generate_reasons(findings: List[RuleFinding]) -> List[str]:
    """
    Generate clean, bulleted explainability reasons from rule findings.
    """
    if not findings:
        return ["No suspicious lexical or structural patterns were detected in the URL."]

    reasons: List[str] = []
    for f in findings:
        if f.rule_id == "RULE_IP_HOSTNAME":
            reasons.append("Hostname is a direct numeric IP address rather than a registered domain name.")
        elif f.rule_id == "RULE_KEYWORD_PATTERN":
            reasons.append(f"URL contains a cluster of credential-related terms ({f.evidence}).")
        elif f.rule_id == "RULE_KEYWORD_SINGLE":
            reasons.append(f"URL contains authentication terminology ({f.evidence}).")
        elif f.rule_id == "RULE_EXCESSIVE_SUBDOMAINS":
            reasons.append("Domain uses an unusually deep subdomain structure often seen in spoofing.")
        elif f.rule_id == "RULE_USERINFO_SPOOFING":
            reasons.append("URL authority section contains an '@' symbol, which may disguise the real destination.")
        elif f.rule_id == "RULE_ENCODED_OBFUSCATION":
            reasons.append(f"URL contains suspicious obfuscated percent-encoding ({f.evidence}).")
        elif f.rule_id == "RULE_PATH_REDIRECT":
            reasons.append("URL path contains irregular double-slash ('//') redirection sequences.")
        elif f.rule_id == "RULE_SUSPICIOUS_TLD":
            reasons.append(f"Domain uses high-abuse top-level domain ({f.evidence}).")
        elif f.rule_id == "RULE_NON_STANDARD_PORT":
            reasons.append(f"URL communicates over non-standard port ({f.evidence}).")
        elif f.rule_id == "RULE_UNENCRYPTED_HTTP":
            reasons.append("URL uses unencrypted HTTP protocol; data in transit is not protected.")
        elif f.rule_id == "RULE_URL_LENGTH":
            reasons.append(f"URL length is unusually long ({f.evidence}).")
        else:
            reasons.append(f.description)

    return reasons


def generate_summary(risk_level: str, findings: List[RuleFinding], target: str) -> str:
    """
    Generate an executive summary describing the evaluation findings.
    """
    if risk_level == "unknown":
        return "Insufficient evidence for a reliable classification."

    if risk_level in ("critical", "high"):
        reasons_brief = ", ".join(f.name for f in findings[:3])
        return (
            f"Multiple suspicious URL indicators were detected ({reasons_brief}). "
            f"The structure indicates elevated risk consistent with phishing or deceptive redirection."
        )

    if risk_level == "medium":
        return (
            f"Moderate risk indicators identified. "
            f"The URL exhibits non-standard structural characteristics requiring caution."
        )

    if risk_level == "low":
        return "Minor security observations noted (such as unencrypted HTTP), but no aggressive phishing patterns were observed."

    return "No anomalous structural or lexical indicators detected. The URL matches standard legitimate patterns."


def generate_recommendation(risk_level: str, findings: List[RuleFinding]) -> str:
    """
    Generate actionable advice for the end user based on risk severity and triggered rules.
    """
    if risk_level == "unknown":
        return "Do not proceed if the source of this link is untrusted. Verify through official independent channels."

    rule_ids = {f.rule_id for f in findings}

    if risk_level in ("critical", "high"):
        if "RULE_KEYWORD_PATTERN" in rule_ids or "RULE_IP_HOSTNAME" in rule_ids:
            return "Avoid entering passwords, OTPs, or payment information. Do not download or execute any files from this address."
        return "Exercise extreme caution: avoid interacting with forms or supplying credentials on this page."

    if risk_level == "medium":
        return "Verify the destination domain carefully before proceeding. Avoid entering sensitive credentials."

    if "RULE_UNENCRYPTED_HTTP" in rule_ids:
        return "Do not submit sensitive personal details or passwords over this unencrypted (HTTP) connection."

    return "Standard browsing vigilance applies: verify that the domain matches your intended destination."
