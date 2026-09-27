"""
Web Security & Redirect Risk Rules Detector

Evaluates deterministic cybersecurity rules against the live web fetch,
redirect chain, HTML content analysis, and download payload inspection.

Follows ScamBuster evidence model, preserves provenance, and deduplicates penalties.
"""

from typing import Any, Dict, List, Tuple


def evaluate_web_risk_rules(
    web_analysis: Dict[str, Any],
    existing_url_score: int = 0
) -> Tuple[int, List[Dict[str, Any]]]:
    """
    Evaluate deterministic web security rules against the web analysis result.
    Returns:
        (web_rule_score, indicators)
    """
    if not web_analysis:
        return 0, []

    indicators: List[Dict[str, Any]] = []
    score = 0

    status = web_analysis.get("status", "unknown")
    failure_reason = web_analysis.get("failure_reason", "")
    redirects = web_analysis.get("redirects") or {}
    response = web_analysis.get("response") or {}
    content = web_analysis.get("content") or {}
    download = web_analysis.get("download") or {}

    # 1. SSRF Violation Rule
    if status == "blocked" and "SSRF" in failure_reason:
        score += 85
        indicators.append({
            "rule_id": "WEB_RULE_SSRF_BLOCKED",
            "name": "SSRF Security Violation Blocked",
            "severity": "CRITICAL",
            "description": "Outbound connection was blocked by ScamBuster's SSRF security policy. Target resolved to private, loopback, or cloud metadata infrastructure.",
            "evidence": failure_reason,
            "source": "WEB_SECURITY_POLICY",
        })
        return min(score, 100), indicators

    # 2. Redirect Loop Rule
    if redirects.get("loop_detected"):
        score += 35
        indicators.append({
            "rule_id": "WEB_RULE_REDIRECT_LOOP",
            "name": "HTTP Redirect Loop Detected",
            "severity": "HIGH",
            "description": "The destination server initiated a circular redirection loop, commonly used by evasion frameworks or misconfigured cloaking infrastructure.",
            "evidence": f"Initial: {redirects.get('initial_domain')}, Loop detected in chain",
            "source": "REDIRECT_ANALYZER",
        })

    # 3. Maximum Redirect Limit Reached
    if redirects.get("limit_reached"):
        score += 25
        indicators.append({
            "rule_id": "WEB_RULE_REDIRECT_LIMIT_REACHED",
            "name": "Excessive Redirect Chain (Limit Reached)",
            "severity": "MEDIUM",
            "description": f"Redirection chain exceeded the maximum safety limit ({redirects.get('redirect_count', 0)} hops). Often associated with traffic distribution systems (TDS).",
            "evidence": f"Total hops: {redirects.get('redirect_count', 0)}",
            "source": "REDIRECT_ANALYZER",
        })

    # 4. Domain Hopping Across Multiple Distinct Registrable Domains
    if redirects.get("domain_hopping"):
        score += 35
        distinct_count = redirects.get("distinct_domain_count", 0)
        chain_domains = [h.get("target_domain") for h in redirects.get("chain", []) if h.get("target_domain")]
        indicators.append({
            "rule_id": "WEB_RULE_DOMAIN_HOPPING",
            "name": "Rapid Domain Hopping Detected",
            "severity": "HIGH",
            "description": f"URL traversed {distinct_count} distinct registered domains in a short redirection sequence, a characteristic pattern of affiliate cloaking and phishing redirection.",
            "evidence": f"Domains: {', '.join(list(set(chain_domains))[:5])}",
            "source": "REDIRECT_ANALYZER",
        })

    # 5. URL Shortener Cloaking
    if redirects.get("shortener_detected") and redirects.get("redirect_count", 0) > 0:
        score += 15
        indicators.append({
            "rule_id": "WEB_RULE_SHORTENER_CLOAKING",
            "name": "URL Shortener Redirection Cloaking",
            "severity": "LOW",
            "description": f"URL uses a known shortening service to mask the real destination ({redirects.get('final_domain')}).",
            "evidence": f"Shortener domain resolved to {redirects.get('final_domain')}",
            "source": "REDIRECT_ANALYZER",
        })

    # 6. HTML Meta Refresh or Static JavaScript Redirection
    if redirects.get("meta_refresh_detected"):
        score += 15
        indicators.append({
            "rule_id": "WEB_RULE_META_REFRESH",
            "name": "HTML Meta Refresh Redirection",
            "severity": "LOW",
            "description": "The page instructs the browser to redirect automatically via an HTML <meta http-equiv='refresh'> directive.",
            "evidence": "Meta refresh directive present in HTML head",
            "source": "CONTENT_ANALYZER",
        })

    if redirects.get("js_redirect_detected"):
        score += 20
        indicators.append({
            "rule_id": "WEB_RULE_JS_REDIRECT",
            "name": "Client-Side Script Navigation Trigger",
            "severity": "MEDIUM",
            "description": "Static script inspection identified an automatic location replacement call (window.location / location.href).",
            "evidence": "Static JavaScript location modification identified",
            "source": "CONTENT_ANALYZER",
        })

    # 7. Credential Harvesting Form on Untrusted Destination
    if content.get("has_credential_form"):
        pwd_forms = content.get("password_form_count", 0)
        pay_forms = content.get("payment_form_count", 0)
        is_https = response.get("is_https", True)

        if not is_https:
            # Unencrypted credential submission
            score += 45
            indicators.append({
                "rule_id": "WEB_RULE_UNENCRYPTED_CREDENTIAL_FORM",
                "name": "Unencrypted Cleartext Credential Form (HTTP)",
                "severity": "HIGH",
                "description": "The website hosts a login or payment input field over an unencrypted cleartext HTTP channel without TLS.",
                "evidence": f"Password fields: {pwd_forms}, Payment fields: {pay_forms}, Protocol: HTTP",
                "source": "CONTENT_ANALYZER",
            })
        else:
            # Form on HTTPS but check if destination has other risk signals
            base_form_score = 25 if (existing_url_score > 30 or redirects.get("cross_domain_count", 0) > 0) else 10
            score += base_form_score
            indicators.append({
                "rule_id": "WEB_RULE_CREDENTIAL_HARVESTING_FORM",
                "name": "Authentication / Credential Input Form Present",
                "severity": "MEDIUM" if base_form_score > 15 else "LOW",
                "description": f"Detected {pwd_forms} authentication form(s) and {pay_forms} payment/financial field(s) on destination page.",
                "evidence": f"Password forms: {pwd_forms}, Payment forms: {pay_forms}",
                "source": "CONTENT_ANALYZER",
            })

    # 8. Hidden and Cross-Domain iframes
    hidden_iframes = content.get("hidden_iframe_count", 0)
    if hidden_iframes > 0:
        score += 25
        indicators.append({
            "rule_id": "WEB_RULE_HIDDEN_IFRAME",
            "name": "Hidden Zero-Dimension iframe Detected",
            "severity": "MEDIUM",
            "description": f"Detected {hidden_iframes} hidden or 0-pixel iframe(s), a technique frequently employed for clickjacking, drive-by session injection, or tracking.",
            "evidence": f"{hidden_iframes} hidden iframe(s) found in DOM structure",
            "source": "CONTENT_ANALYZER",
        })

    # 9. Download Analysis Rules
    if download and download.get("download_detected"):
        file_type = download.get("file_type", "UNKNOWN")
        filename = download.get("filename", "")
        sha256 = download.get("sha256", "")

        if file_type == "EXE" or download.get("is_executable"):
            score += 40
            indicators.append({
                "rule_id": "WEB_RULE_DOWNLOAD_EXECUTABLE",
                "name": "Executable File Download Initiated",
                "severity": "HIGH",
                "description": f"Web response initiates a direct download of an executable binary or installation script ({filename}). Executable downloads require verified origin verification.",
                "evidence": f"File: {filename}, SHA-256: {sha256[:16]}...",
                "source": "DOWNLOAD_ANALYZER",
            })

        elif file_type == "APK" or download.get("is_apk"):
            apk_analysis = download.get("apk_analysis") or {}
            apk_rule_score = apk_analysis.get("rule_risk_score", 0)
            apk_privacy_score = apk_analysis.get("privacy_risk_score", 0)

            # Combined APK assessment
            score += 25 + int(max(apk_rule_score, apk_privacy_score) * 0.4)
            severity = "HIGH" if (apk_rule_score >= 50 or apk_privacy_score >= 60) else "MEDIUM"
            indicators.append({
                "rule_id": "WEB_RULE_DOWNLOAD_APK",
                "name": "Android APK Package Download Initiated",
                "severity": severity,
                "description": f"Web response initiates a direct Android APK package download ({filename}). Inspected by Phase 07/08 static analyzers without execution.",
                "evidence": f"Package: {apk_analysis.get('package_name', filename)}, APK Malware Score: {apk_rule_score}/100, Privacy Score: {apk_privacy_score}/100",
                "source": "APK_HANDOFF_ANALYZER",
            })

    # 10. Obfuscation indicators in HTML / script
    obf_list = content.get("obfuscation_indicators", [])
    if obf_list:
        score += 20
        indicators.append({
            "rule_id": "WEB_RULE_SCRIPT_OBFUSCATION",
            "name": "Script Obfuscation Primitives Detected",
            "severity": "MEDIUM",
            "description": "Static inspection found concentrated encoded character primitives or evaluation wrappers in page content.",
            "evidence": "; ".join(obf_list[:2]),
            "source": "CONTENT_ANALYZER",
        })

    # Cap score at 100
    capped_score = min(max(score, 0), 100)
    return capped_score, indicators
