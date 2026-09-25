"""
ScamBuster Heuristic Cyber Analyzer — URL & Domain Analysis

Deterministic cybersecurity analysis detecting:
- IP address hostnames
- Suspicious / free / high-abuse TLDs
- Brand impersonation / typosquatting in subdomains and paths
- Excessive subdomains (deep nesting)
- URL shortening & redirect obfuscation
- Embedded credentials and '@' host masking
- Phishing keyword clustering
- Non-standard ports & suspicious protocols
"""

import re
import urllib.parse
from typing import Any, Dict, List

# High abuse TLDs frequently seen in spam/phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "loan", "buzz", "fit", "gq", "cf", "ml", "tk",
    "ga", "rest", "country", "stream", "download", "gdn", "racing", "win", "bid",
    "party", "date", "faith", "review", "trade", "accountant", "vip", "monster",
    "hair", "quest", "beauty", "sbs", "cfd"
}

# Legitimate brand domains mapping: brand -> legitimate domain suffix
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "apple": "apple.com",
    "icloud": "icloud.com",
    "netflix": "netflix.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "chase": "chase.com",
    "wellsfargo": "wellsfargo.com",
    "amazon": "amazon.com",
    "binance": "binance.com",
    "metamask": "metamask.io",
    "coinbase": "coinbase.com",
    "steam": "steampowered.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "bankofamerica": "bankofamerica.com",
    "hsbc": "hsbc.com",
    "barclays": "barclays.co.uk",
    "citibank": "citi.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "usps": "usps.com",
}

# Known URL shorteners
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "ow.ly",
    "goo.gl", "buff.ly", "adf.ly", "shorturl.at"
}

# Phishing and credential harvesting trigger keywords
PHISHING_KEYWORDS = {
    "login", "signin", "verify", "verification", "update", "banking",
    "secure", "account", "wallet", "claim", "recovery", "suspended",
    "confirm", "unlock", "security", "authenticate", "passcode", "credential"
}

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")


def analyze_url(url: str) -> Dict[str, Any]:
    """
    Perform deep deterministic heuristic cyber analysis on the given URL.
    Returns score (0-100), threat indicators, and structural metadata.
    """
    clean_url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", clean_url):
        clean_url = "http://" + clean_url

    parsed = urllib.parse.urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    port = parsed.port

    indicators: List[Dict[str, Any]] = []
    score = 0

    # 1. IP address in hostname
    if IPV4_PATTERN.match(hostname) or (hostname.replace(".", "").isdigit()):
        score += 40
        indicators.append({
            "name": "Direct IP Address Hostname",
            "severity": "HIGH",
            "description": "The URL host is a raw numeric IP address instead of a registered domain name, common in phishing and C2 servers.",
            "evidence": hostname,
        })

    # 2. Suspicious TLD check
    tld = hostname.split(".")[-1] if "." in hostname else ""
    if tld in SUSPICIOUS_TLDS:
        score += 25
        indicators.append({
            "name": "High-Risk Top Level Domain (TLD)",
            "severity": "MEDIUM",
            "description": f"The domain uses '.{tld}', a top-level domain frequently associated with automated spam campaigns and low-cost phishing sites.",
            "evidence": f".{tld}",
        })

    # 3. URL Shortener Detection
    if hostname in SHORTENER_DOMAINS:
        score += 15
        indicators.append({
            "name": "URL Shortener / Redirect Cloaking",
            "severity": "LOW",
            "description": "URL shorteners conceal the true destination server and are frequently leveraged to bypass automated filters.",
            "evidence": hostname,
        })

    # 4. Brand Impersonation / Typosquatting
    full_text_to_check = f"{hostname}/{path}?{query}".lower()
    for brand, legit_domain in KNOWN_BRANDS.items():
        if brand in full_text_to_check:
            # Check if it actually belongs to the legitimate domain
            if not hostname.endswith(legit_domain) and hostname != legit_domain:
                score += 35
                indicators.append({
                    "name": f"Brand Impersonation: {brand.capitalize()}",
                    "severity": "HIGH",
                    "description": f"The URL references brand '{brand}', but the host is not the legitimate registered domain '{legit_domain}'.",
                    "evidence": f"Target: {brand}, Host: {hostname}",
                })
                break  # Flag highest brand match

    # 5. Excessive Subdomain Nesting
    subdomains = hostname.split(".")
    if len(subdomains) > 4:
        score += 20
        indicators.append({
            "name": "Excessive Subdomain Nesting",
            "severity": "MEDIUM",
            "description": "Deeply nested subdomains are often crafted to emulate legitimate domains while redirecting to an attacker-controlled base host.",
            "evidence": f"{len(subdomains)} domain labels found in '{hostname}'",
        })

    # 6. '@' Symbol in URL (userinfo spoofing)
    if "@" in parsed.netloc or "@" in clean_url:
        score += 35
        indicators.append({
            "name": "Userinfo Host Spoofing ('@' Symbol)",
            "severity": "HIGH",
            "description": "An '@' symbol was detected in the URL authority section. Browsers ignore everything prior to '@', deceiving users on the true host.",
            "evidence": clean_url,
        })

    # 7. Dangerous Double Slash in Path
    if "//" in path:
        score += 20
        indicators.append({
            "name": "Double Slash Path Obfuscation",
            "severity": "MEDIUM",
            "description": "Irregular double slashes ('//') in the URL path indicate open-redirect vulnerabilities or path traversal attempts.",
            "evidence": path,
        })

    # 8. Non-standard HTTP/HTTPS Port
    if port and port not in (80, 443, 8000, 8080):
        score += 15
        indicators.append({
            "name": "Non-Standard Communication Port",
            "severity": "LOW",
            "description": f"The URL targets custom port {port}, unusual for standard public web portals.",
            "evidence": f"Port: {port}",
        })

    # 9. Phishing Keywords in Path or Query
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in path.lower() or kw in query.lower()]
    if len(matched_keywords) >= 2:
        score += 20
        indicators.append({
            "name": "Credential Harvesting Keywords Cluster",
            "severity": "MEDIUM",
            "description": f"Multiple authentication and urgency keywords detected in URL path/query: {', '.join(matched_keywords)}.",
            "evidence": ", ".join(matched_keywords),
        })
    elif len(matched_keywords) == 1 and score > 0:
        score += 10
        indicators.append({
            "name": "Suspicious Authentication Keyword",
            "severity": "LOW",
            "description": f"Authentication keyword '{matched_keywords[0]}' detected on an unverified domain.",
            "evidence": matched_keywords[0],
        })

    # Cap score at 100
    capped_score = min(max(score, 0), 100)

    return {
        "score": capped_score,
        "indicators": indicators,
        "details": {
            "hostname": hostname,
            "tld": tld,
            "path": path,
            "port": port,
            "is_ip": bool(IPV4_PATTERN.match(hostname)),
            "indicator_count": len(indicators),
        }
    }
