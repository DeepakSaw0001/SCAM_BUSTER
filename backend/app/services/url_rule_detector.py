"""
ScamBuster URL Rule-Based Detector

Evaluates independent cybersecurity heuristics against normalized URLs
and extracted features.

Key Principles:
- A single indicator does NOT automatically classify a URL as malicious.
- Combines independent evidence without fabricating artificial confidence.
- Purely static / lexical analysis — NO outbound network requests (zero SSRF).
"""

import re
from typing import List, Optional
from pydantic import BaseModel, Field

from app.services.url_normalizer import NormalizedUrlResult, normalize_url
from app.services.url_feature_extractor import UrlFeatures, extract_url_features

# High-abuse TLDs frequently observed in phishing / spam registration spikes
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "buzz", "fit", "gq", "cf", "ml", "tk",
    "ga", "rest", "country", "stream", "download", "gdn", "racing", "win", "bid",
    "party", "date", "faith", "review", "trade", "accountant", "vip", "monster"
}

# Suspicious percent-encoding sequences (directory traversal, path tampering, null-byte)
OBFUSCATED_PATTERNS = [
    (re.compile(r"%2f", re.IGNORECASE), "Percent-encoded slash (%2F)"),
    (re.compile(r"%2e%2e", re.IGNORECASE), "Percent-encoded path traversal (%2E%2E)"),
    (re.compile(r"%00", re.IGNORECASE), "Null-byte injection sequence (%00)"),
    (re.compile(r"%40", re.IGNORECASE), "Percent-encoded userinfo symbol (%40)"),
]


class RuleFinding(BaseModel):
    rule_id: str
    name: str
    severity: str = Field(..., description="critical, high, medium, low, or info")
    score_weight: int = Field(..., ge=0, le=100)
    description: str
    evidence: str


def evaluate_url_rules(
    url: str,
    normalized: Optional[NormalizedUrlResult] = None,
    features: Optional[UrlFeatures] = None
) -> List[RuleFinding]:
    """
    Evaluate all independent lexical security rules against the URL.
    Returns a list of triggered RuleFinding objects.
    """
    norm = normalized or normalize_url(url)
    feats = features or extract_url_features(url, norm)

    findings: List[RuleFinding] = []

    # 1. IP-based Hostname Check
    if feats.has_ip_hostname:
        findings.append(RuleFinding(
            rule_id="RULE_IP_HOSTNAME",
            name="IP-based Hostname",
            severity="high",
            score_weight=35,
            description="The URL uses a raw IP address instead of a registered domain name, common in phishing and command-and-control infrastructure.",
            evidence=f"Hostname: {norm.hostname}",
        ))

    # 2. URL Length Anomaly Check
    if feats.url_length >= 100:
        findings.append(RuleFinding(
            rule_id="RULE_URL_LENGTH",
            name="Excessive URL Length",
            severity="medium",
            score_weight=15,
            description="The URL is unusually long (>=100 characters), a technique often used to obscure malicious query parameters or truncate domain views on mobile screens.",
            evidence=f"Total length: {feats.url_length} characters",
        ))

    # 3. Excessive Subdomains Check
    if feats.subdomain_count >= 3:
        findings.append(RuleFinding(
            rule_id="RULE_EXCESSIVE_SUBDOMAINS",
            name="Excessive Subdomain Nesting",
            severity="medium",
            score_weight=20,
            description="The domain features three or more subdomain levels, which can be crafted to mimic brand names while routing to an attacker domain.",
            evidence=f"{feats.subdomain_count} subdomain levels detected in '{norm.hostname}'",
        ))

    # 4. Suspicious Keyword Combinations
    if feats.suspicious_keyword_count >= 2:
        findings.append(RuleFinding(
            rule_id="RULE_KEYWORD_PATTERN",
            name="Suspicious Keyword Pattern",
            severity="high",
            score_weight=25,
            description="The URL contains a cluster of credential and urgency-related keywords frequently leveraged in credential harvesting portals.",
            evidence=f"Matched keywords: {', '.join(feats.matched_keywords)}",
        ))
    elif feats.suspicious_keyword_count == 1:
        findings.append(RuleFinding(
            rule_id="RULE_KEYWORD_SINGLE",
            name="Credential Keyword Present",
            severity="low",
            score_weight=10,
            description="The URL contains authentication or account terminology.",
            evidence=f"Matched keyword: '{feats.matched_keywords[0]}'",
        ))

    # 5. Obfuscated / Encoded Characters Check
    raw_target = norm.original_url
    for pattern, label in OBFUSCATED_PATTERNS:
        if pattern.search(raw_target):
            findings.append(RuleFinding(
                rule_id="RULE_ENCODED_OBFUSCATION",
                name="Suspicious Encoded Characters",
                severity="medium",
                score_weight=20,
                description=f"Detected suspicious percent-encoding ({label}) used to bypass lexical safety filters.",
                evidence=label,
            ))
            break

    # 6. Double Slash in Path (Open redirect indicator)
    if feats.has_double_slash_redirect:
        findings.append(RuleFinding(
            rule_id="RULE_PATH_REDIRECT",
            name="Path Redirection Sequence",
            severity="medium",
            score_weight=20,
            description="Irregular double slashes ('//') detected within the path component, indicating potential open redirect or path traversal patterns.",
            evidence=f"Path: {norm.path}",
        ))

    # 7. Userinfo Spoofing Check ('@' in URL)
    if feats.has_at_symbol:
        findings.append(RuleFinding(
            rule_id="RULE_USERINFO_SPOOFING",
            name="Userinfo Host Spoofing",
            severity="high",
            score_weight=30,
            description="An '@' symbol was detected in the URL authority section. Browsers ignore everything prior to '@', deceiving users on the true destination host.",
            evidence=raw_target,
        ))

    # 8. Unusual Communication Port
    if feats.has_port:
        findings.append(RuleFinding(
            rule_id="RULE_NON_STANDARD_PORT",
            name="Unusual Communication Port",
            severity="low",
            score_weight=15,
            description=f"The URL targets custom port {norm.port}, which is irregular for standard public web portals.",
            evidence=f"Port: {norm.port}",
        ))

    # 9. High-Risk Top-Level Domain (TLD)
    tld = norm.hostname.split(".")[-1] if "." in norm.hostname else ""
    if tld in SUSPICIOUS_TLDS:
        findings.append(RuleFinding(
            rule_id="RULE_SUSPICIOUS_TLD",
            name="High-Risk Top-Level Domain",
            severity="medium",
            score_weight=20,
            description=f"The domain uses '.{tld}', a top-level domain frequently associated with low-cost disposable infrastructure and phishing campaigns.",
            evidence=f".{tld}",
        ))

    # 10. Unencrypted Transport Protocol (HTTP vs HTTPS)
    # Note: HTTP alone is NOT malicious, but represents a lack of transport security
    if not feats.uses_https:
        findings.append(RuleFinding(
            rule_id="RULE_UNENCRYPTED_HTTP",
            name="Unencrypted HTTP Transport",
            severity="low",
            score_weight=10,
            description="The URL uses unencrypted HTTP instead of HTTPS. While not inherently malicious, it allows traffic eavesdropping and credential interception.",
            evidence="Protocol scheme: http://",
        ))

    return findings
