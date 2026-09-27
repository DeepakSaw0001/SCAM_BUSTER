"""
ScamBuster Risk Engine — Explanations & Actionable Guidance (Phase 03)

Generates human-readable, evidence-based explanations and defensive recommendations
distinguishing between static rule evidence and machine learning evidence.

Key Principles:
- Describes concrete evidence neutrally without absolute claims.
- Explicitly separates Rule Detection evidence from ML Classifier evidence.
- Never claims "ML says malicious, therefore malicious."
- Provides clear, actionable defensive recommendations.
"""

from typing import Any, Dict, List, Optional
from app.services.url_rule_detector import RuleFinding


def generate_reasons(
    findings: List[RuleFinding],
    ml_result: Optional[Dict[str, Any]] = None
) -> List[str]:
    """
    Generate clean, bulleted explainability reasons clearly delineating rule
    indicators and ML statistical evidence.
    """
    reasons: List[str] = []

    # 1. Rule-Based Evidence
    if findings:
        for f in findings:
            if f.rule_id == "RULE_IP_HOSTNAME":
                reasons.append("Rule Evidence: Hostname is a direct numeric IP address rather than a registered domain name.")
            elif f.rule_id == "RULE_KEYWORD_PATTERN":
                reasons.append(f"Rule Evidence: URL contains a cluster of credential-related terms ({f.evidence}).")
            elif f.rule_id == "RULE_KEYWORD_SINGLE":
                reasons.append(f"Rule Evidence: URL contains authentication terminology ({f.evidence}).")
            elif f.rule_id == "RULE_EXCESSIVE_SUBDOMAINS":
                reasons.append("Rule Evidence: Domain uses an unusually deep subdomain structure often seen in spoofing.")
            elif f.rule_id == "RULE_USERINFO_SPOOFING":
                reasons.append("Rule Evidence: URL authority section contains an '@' symbol, which may disguise the real destination.")
            elif f.rule_id == "RULE_ENCODED_OBFUSCATION":
                reasons.append(f"Rule Evidence: URL contains suspicious obfuscated percent-encoding ({f.evidence}).")
            elif f.rule_id == "RULE_PATH_REDIRECT":
                reasons.append("Rule Evidence: URL path contains irregular double-slash ('//') redirection sequences.")
            elif f.rule_id == "RULE_SUSPICIOUS_TLD":
                reasons.append(f"Rule Evidence: Domain uses high-abuse top-level domain ({f.evidence}).")
            elif f.rule_id == "RULE_NON_STANDARD_PORT":
                reasons.append(f"Rule Evidence: URL communicates over non-standard port ({f.evidence}).")
            elif f.rule_id == "RULE_UNENCRYPTED_HTTP":
                reasons.append("Rule Evidence: URL uses unencrypted HTTP protocol; data in transit is not protected.")
            elif f.rule_id == "RULE_URL_LENGTH":
                reasons.append(f"Rule Evidence: URL length is unusually long ({f.evidence}).")
            else:
                reasons.append(f"Rule Evidence: {f.description}")
    else:
        reasons.append("Rule Evidence: No suspicious lexical or signature patterns detected by heuristic rule engine.")

    # 2. Machine Learning Evidence
    if ml_result and ml_result.get("available", False):
        version = ml_result.get("model_version", "url-model-1.0")
        prediction = ml_result.get("prediction", "unknown")
        score = ml_result.get("model_score", 0.0)

        if prediction == "malicious":
            reasons.append(
                f"ML Evidence: Statistical URL classifier ({version}) predicted malicious class with model score {score:.2f}."
            )
            top_feats = ml_result.get("top_contributing_features", [])
            if top_feats:
                top_summary = ", ".join(f"{t['feature']}={t['value']}" for t in top_feats[:3])
                reasons.append(f"ML Features: Elevated risk correlates with {top_summary}.")
        elif prediction == "benign":
            reasons.append(
                f"ML Evidence: Statistical URL classifier ({version}) predicted benign class with model score {score:.2f}."
            )
    elif ml_result and not ml_result.get("available", False):
        reasons.append("ML Evidence: Classifier offline; assessment relies exclusively on deterministic heuristic rules.")

    return reasons


def generate_summary(
    risk_level: str,
    findings: List[RuleFinding],
    target: str,
    ml_result: Optional[Dict[str, Any]] = None
) -> str:
    """
    Generate an executive summary describing the combined rule + ML evaluation findings.
    """
    if risk_level == "unknown":
        return "Insufficient evidence for a reliable classification."

    has_ml = ml_result and ml_result.get("available", False)
    ml_pred = ml_result.get("prediction") if has_ml else None

    if risk_level in ("critical", "high"):
        reasons_brief = ", ".join(f.name for f in findings[:2]) if findings else "structural anomalies"
        ml_phrase = f" Corroborated by ML prediction ({ml_pred})." if ml_pred == "malicious" else ""
        return (
            f"Elevated threat detected ({reasons_brief}).{ml_phrase} "
            f"The combined structural and lexical signals indicate high probability of phishing or credential harvesting."
        )

    if risk_level == "medium":
        return (
            f"Moderate risk indicators identified. "
            f"The URL exhibits non-standard structural characteristics requiring caution before navigation."
        )

    if risk_level == "low":
        return "Minor observations noted (such as unencrypted HTTP), but no aggressive phishing patterns were observed."

    return "No anomalous structural, lexical, or ML indicators detected. The URL matches standard legitimate patterns."


def generate_recommendation(
    risk_level: str,
    findings: List[RuleFinding],
    ml_result: Optional[Dict[str, Any]] = None
) -> str:
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


def generate_message_reasons(
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> List[str]:
    """
    Generate clean, evidence-based explainability reasons for SMS / text messages,
    delineating rule indicators, NLP machine learning signals, social engineering vectors, and embedded URL threats.
    """
    reasons: List[str] = []

    # 1. Rule-Based Evidence
    if findings:
        for f in findings:
            rule_id = getattr(f, "rule_id", "")
            evidence = getattr(f, "evidence", "")
            description = getattr(f, "description", "")
            if rule_id == "RULE_CREDENTIAL_SOLICITATION":
                reasons.append(f"Rule Evidence: Requests confidential security credentials, passwords, or one-time verification tokens ({evidence}).")
            elif rule_id == "RULE_ACCOUNT_VERIFICATION_LURE":
                reasons.append("Rule Evidence: Instructs recipient to verify account access or sensitive profile details under potential pretense.")
            elif rule_id == "RULE_URGENCY_PRESSURE":
                reasons.append(f"Rule Evidence: High-pressure psychological urgency manipulation ({evidence}) designed to induce hasty compliance.")
            elif rule_id == "RULE_THREAT_COERCION":
                reasons.append(f"Rule Evidence: Intimidation language threatening negative consequences, service termination, or legal penalties ({evidence}).")
            elif rule_id == "RULE_UNSOLICITED_REWARD":
                reasons.append(f"Rule Evidence: Unsolicited monetary or lottery reward lure ({evidence}) typical of advance-fee scams.")
            elif rule_id == "RULE_EMBEDDED_LINK":
                reasons.append(f"Rule Evidence: Direct hyperlink embedded inside message ({evidence}) posing potential smishing redirection threat.")
            elif rule_id == "RULE_HIGH_UPPERCASE":
                reasons.append(f"Rule Evidence: Abnormally high uppercase capitalization ({evidence}) used to simulate urgency or alarm.")
            elif rule_id == "RULE_REPEATED_PUNCTUATION":
                reasons.append(f"Rule Evidence: Excessive repeated exclamation punctuation ({evidence}) commonly accompanying sensationalized lures.")
            elif rule_id == "RULE_SENDER_SHORTCODE":
                reasons.append(f"Rule Evidence: Message originates from an unverified numeric shortcode ({evidence}).")
            else:
                reasons.append(f"Rule Evidence: {description}")

    # 2. Social Engineering Findings
    if social_engineering_findings:
        for se in social_engineering_findings:
            s_name = getattr(se, "name", "")
            s_ev = getattr(se, "evidence", "")
            s_sev = getattr(se, "severity", "HIGH")
            reasons.append(f"Social Engineering Evidence: {s_name} [{s_sev}] — {s_ev}")

    if not findings and not social_engineering_findings:
        reasons.append("Rule Evidence: No suspicious social-engineering or credential-solicitation rules triggered.")

    # 3. NLP Machine Learning Evidence
    if ml_result and ml_result.get("available", False):
        version = ml_result.get("model_version", "message-model-1.0")
        prediction = ml_result.get("prediction", "unknown")
        score = ml_result.get("model_score", 0.0)
        prob = ml_result.get("model_probability", 0.0)

        if prediction == "scam":
            reasons.append(
                f"ML Evidence: Statistical NLP classifier ({version}) detected scam language patterns with model score {score:.2f} ({prob * 100:.1f}% probability)."
            )
        elif prediction == "legitimate":
            reasons.append(
                f"ML Evidence: Statistical NLP classifier ({version}) predicted legitimate/benign communication with model score {score:.2f}."
            )
    elif ml_result and not ml_result.get("available", False):
        reasons.append("ML Evidence: Classifier offline; assessment relies on deterministic cybersecurity rules.")

    # 4. Embedded URL Evidence
    if embedded_urls:
        for u in embedded_urls:
            url_score = u.get("risk_score", 0)
            url_level = str(u.get("risk_level", "unknown")).upper()
            host = u.get("hostname", u.get("url", ""))
            reasons.append(
                f"Embedded URL Evidence: Link to '{host}' evaluated as {url_level} risk (Static URL Risk Score: {url_score}/100)."
            )

    return reasons


def generate_message_summary(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generate an executive summary describing the combined rule + NLP ML + URL evaluation for an SMS message.
    """
    if risk_level == "unknown":
        return "Insufficient evidence for a reliable scam determination. The message text is too brief or ambiguous to confidently classify."

    has_ml = ml_result and ml_result.get("available", False)
    ml_pred = ml_result.get("prediction") if has_ml else None

    if risk_level in ("critical", "high"):
        reasons_brief = ", ".join(getattr(f, "name", "suspicious indicator") for f in findings[:2]) if findings else "deceptive patterns"
        ml_phrase = " Corroborated by NLP classifier predicting scam." if ml_pred == "scam" else ""
        url_phrase = f" Contains {len(embedded_urls)} embedded link(s)." if embedded_urls else ""
        return (
            f"High risk scam / smishing threat detected ({reasons_brief}).{ml_phrase}{url_phrase} "
            f"The message demonstrates characteristic patterns of deceptive social engineering or credential harvesting."
        )

    if risk_level == "medium":
        return (
            "Suspicious message characteristics identified. The message contains coercive or promotional indicators "
            "often seen in unsolicited marketing, phishing lures, or unverified alerts."
        )

    if risk_level == "low":
        return "Minor observations noted, but no aggressive credential solicitation or coercion patterns were detected."

    return "No anomalous social-engineering, credential-harvesting, or scam indicators detected. The text appears to be legitimate communication."


def generate_message_recommendation(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> str:
    """
    Generate actionable defensive security guidance for message recipients.
    """
    if risk_level == "unknown":
        return "Do not reply or click links if this message is from an unfamiliar contact. Verify the sender independently."

    all_findings = list(findings) + list(social_engineering_findings or [])
    rule_ids = {getattr(f, "rule_id", "") for f in all_findings}

    if "RULE_SE_OTP_HARVEST" in rule_ids:
        return (
            "Do not disclose or forward the requested authentication code. "
            "Legitimate organizations generally should not ask you to disclose authentication codes to another person."
        )

    if "RULE_SE_ANCHOR_MISMATCH" in rule_ids:
        return "Do not tap or click the link. The displayed anchor text misleadingly points to an external destination."

    if any("BRAND" in r for r in rule_ids):
        return "Do not trust the claimed brand identity in this message. Independently verify using official customer support channels."

    if risk_level in ("critical", "high"):
        if "RULE_CREDENTIAL_SOLICITATION" in rule_ids or "RULE_SE_CREDENTIAL_HARVEST" in rule_ids:
            return "Do not provide OTPs, passwords, payment information, or account credentials. Legitimate institutions will never ask for your verification codes via SMS."
        if embedded_urls:
            return "Do not click any embedded links or provide sensitive information. Report and delete this message."
        return "Exercise extreme caution: do not reply, send money, or follow instructions in this message. Forward to 7726 (SPAM) to notify your carrier."

    if risk_level == "medium":
        return "Verify the claimed sender through official contact channels before clicking links, replying, or taking action."

    return "Standard vigilance applies: never share one-time security codes or passwords over text message."


def generate_email_reasons(
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
    preprocessed_data: Optional[Any] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> List[str]:
    """
    Generate clean, evidence-based explainability reasons for emails,
    delineating rule indicators, NLP machine learning signals, social engineering vectors,
    embedded URL threats, and attachment risks.
    """
    reasons: List[str] = []

    # 1. Rule-Based Evidence
    if findings:
        for f in findings:
            rule_id = getattr(f, "rule_id", "")
            evidence = getattr(f, "evidence", "")
            description = getattr(f, "description", "")

            if rule_id == "RULE_EMAIL_ANCHOR_MISMATCH":
                reasons.append(f"Deceptive hyperlink detected: link destination points to a different host than visually advertised ({evidence}).")
            elif rule_id == "RULE_EMAIL_SENDER_REPLYTO_MISMATCH":
                reasons.append(f"Address spoofing indicator: From address domain does not align with Reply-To domain ({evidence}).")
            elif rule_id == "RULE_EMAIL_AUTH_FAILURE":
                reasons.append(f"Mail authentication failure reported in headers ({evidence}).")
            elif rule_id == "RULE_EMAIL_DOUBLE_EXTENSION_ATTACHMENT":
                reasons.append(f"Malicious attachment signature: deceptive double file extension detected ({evidence}).")
            elif rule_id == "RULE_EMAIL_SUSPICIOUS_ATTACHMENT":
                reasons.append(f"High-risk attachment format detected ({evidence}).")
            elif rule_id == "RULE_EMAIL_CREDENTIAL_SOLICITATION":
                reasons.append(f"Message explicitly solicits passwords, verification credentials, or login actions ({evidence}).")
            elif rule_id == "RULE_EMAIL_URGENCY_THREAT":
                reasons.append(f"Psychological urgency or account suspension threats detected ({evidence}).")
            elif rule_id == "RULE_EMAIL_FINANCIAL_LURE":
                reasons.append(f"Advance-fee or unsolicited financial reward patterns identified ({evidence}).")
            elif rule_id == "RULE_EMAIL_HTML_FORM":
                reasons.append(f"Embedded interactive HTML form detected inside email body ({evidence}).")
            else:
                reasons.append(f"{description} ({evidence})")

    # 2. Social Engineering Findings
    if social_engineering_findings:
        for se in social_engineering_findings:
            s_name = getattr(se, "name", "")
            s_ev = getattr(se, "evidence", "")
            s_sev = getattr(se, "severity", "HIGH")
            reasons.append(f"Social Engineering Evidence: {s_name} [{s_sev}] — {s_ev}")

    # 3. Machine Learning Evidence
    if ml_result and ml_result.get("available", False):
        prediction = ml_result.get("prediction", "")
        model_prob = float(ml_result.get("model_probability", 0.0))
        top_features = ml_result.get("top_contributing_features", [])

        if prediction == "phishing" and model_prob >= 0.60:
            feat_desc = ""
            if top_features:
                tokens = [item.get("feature", "") for item in top_features[:3] if item.get("feature")]
                if tokens:
                    feat_desc = f" based on significant phishing vocabulary tokens: [{', '.join(tokens)}]"
            reasons.append(
                f"Statistical NLP model classified email text as phishing with {int(round(model_prob * 100))}% confidence{feat_desc}."
            )

    # 4. Embedded URL Evidence
    if embedded_urls:
        malicious_urls = [u for u in embedded_urls if u.get("risk_score", 0) >= 60]
        if malicious_urls:
            highest = max(malicious_urls, key=lambda x: x.get("risk_score", 0))
            reasons.append(
                f"Embedded URL analysis flagged high-risk link ('{highest.get('url', '')}') with risk score {highest.get('risk_score')}/100."
            )

    if not reasons:
        reasons.append("Email passed all static cybersecurity heuristic rules and NLP classification checks without anomalous indicators.")

    return reasons


def generate_email_summary(
    risk_level: str,
    findings: List[Any],
    sender_domain: str,
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
) -> str:
    """
    Generate an executive summary describing threat posture for an email.
    """
    if risk_level == "unknown":
        return "Insufficient evidence or content provided to establish an analytical email risk assessment."

    rule_ids = {getattr(f, "rule_id", "") for f in findings}
    has_anchor_mismatch = "RULE_EMAIL_ANCHOR_MISMATCH" in rule_ids or "RULE_SE_ANCHOR_MISMATCH" in rule_ids
    has_sender_mismatch = "RULE_EMAIL_SENDER_REPLYTO_MISMATCH" in rule_ids or "RULE_SE_REPLY_TO_DIVERGENCE" in rule_ids
    has_suspicious_att = any("ATTACHMENT" in r for r in rule_ids)
    has_auth_fail = "RULE_EMAIL_AUTH_FAILURE" in rule_ids or "RULE_SE_AUTH_FAILURE" in rule_ids

    if risk_level == "critical":
        elements = []
        if has_anchor_mismatch:
            elements.append("deceptive hyperlinks")
        if has_suspicious_att:
            elements.append("dangerous executable/script attachments")
        if has_auth_fail:
            elements.append("failed mail authentication")
        if not elements:
            elements.append("aggressive credential harvesting and social engineering patterns")
        return f"CRITICAL PHISHING THREAT: Email demonstrates high-confidence deception indicators, including {', '.join(elements)}."

    if risk_level == "high":
        elements = []
        if has_sender_mismatch:
            elements.append("sender/reply-to domain divergence")
        if has_auth_fail:
            elements.append("authentication verification failures")
        if not elements:
            elements.append("credential harvesting lures and artificial urgency")
        return f"HIGH RISK EMAIL: Suspicious patterns detected ({', '.join(elements)}), characteristic of targeted phishing campaigns."

    if risk_level == "medium":
        return (
            "Suspicious email indicators identified. The email contains urgency cues or unverified links "
            "often seen in unsolicited marketing, phishing lures, or bulk correspondence."
        )

    if risk_level == "low":
        return "Minor observations noted, but no aggressive credential solicitation or deceptive attachment patterns were detected."

    return "No anomalous spoofing, credential-harvesting, or attachment threat indicators detected. The email appears to be legitimate correspondence."


def generate_email_recommendation(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    embedded_urls: Optional[List[Dict[str, Any]]] = None,
    social_engineering_findings: Optional[List[Any]] = None,
) -> str:
    """
    Generate actionable defensive security guidance for email recipients.
    """
    if risk_level == "unknown":
        return "Do not click links or open attachments if this email is from an unexpected sender. Verify through official independent channels."

    all_findings = list(findings) + list(social_engineering_findings or [])
    rule_ids = {getattr(f, "rule_id", "") for f in all_findings}

    if "RULE_SE_OTP_HARVEST" in rule_ids:
        return (
            "Do not provide or forward authentication codes. "
            "Legitimate organizations generally should not ask you to disclose authentication codes to another person."
        )

    if any("ATTACHMENT" in r for r in rule_ids):
        return "DO NOT open, download, or execute attachments from this message. Block sender and report as malicious to your security team."

    if "RULE_EMAIL_ANCHOR_MISMATCH" in rule_ids or "RULE_SE_ANCHOR_MISMATCH" in rule_ids:
        return "DO NOT click links or supply passwords. Deceptive links were detected that lead to external phishing sites."

    if any("BRAND" in r for r in rule_ids):
        return "Verify the claimed sender organization directly through independently obtained official contacts."

    if risk_level in ("critical", "high"):
        if "RULE_EMAIL_CREDENTIAL_SOLICITATION" in rule_ids or "RULE_SE_CREDENTIAL_HARVEST" in rule_ids:
            return "Do not enter passwords, credit card numbers, or personal identity details. Navigate directly to the official service website."
        if embedded_urls:
            return "DO NOT click links or supply credentials. Deceptive links were detected that lead to external phishing sites."
        return "Exercise extreme caution: do not reply or click links. Report this message as phishing to your mail administrator."

    if risk_level == "medium":
        return "Verify the sender address and examine link destinations carefully before taking action or replying."

    return "Standard email vigilance applies: never submit passwords or sensitive credentials via unverified links."


# --- Phone Explainability & Guidance (Phase 06) ---

def generate_phone_reasons(
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
    phone_info: Optional[Dict[str, Any]] = None,
) -> List[str]:
    """
    Generate evidence-based, transparent bulleted reasons for phone analysis.
    Delineates Rule Evidence, Statistical ML Probability, and Threat Intelligence.
    Never declares personal identity or character.
    """
    reasons: List[str] = []

    # 1. Heuristic Rule Evidence
    if findings:
        for f in findings:
            reasons.append(f"Rule Evidence: {f.name} — {f.description} ({f.evidence or ''})")
    else:
        reasons.append("Rule Evidence: No anomalous digit structures or known high-risk telephony patterns detected.")

    # 2. Machine Learning Evidence
    if ml_result and ml_result.get("prediction") not in ("unknown", "error", "unavailable"):
        score = ml_result.get("model_score", 0.0)
        pct = int(round(score * 100))
        pred = ml_result.get("prediction", "legitimate")
        reasons.append(
            f"ML Classifier Evidence: Statistical model estimated a {pct}% probability of structural pattern "
            f"correlation with reported scam/robocall profiles (Classification: {pred})."
        )

    # 3. Threat Intelligence Evidence
    if intel_result:
        status = getattr(intel_result, "status", "not_configured")
        provider = getattr(intel_result, "provider", "unknown")
        rep = getattr(intel_result, "reputation", "unknown")
        reports = getattr(intel_result, "report_count", None)

        if status == "available":
            report_str = f" with {reports} recorded consumer complaints" if reports is not None else ""
            reasons.append(
                f"Threat Intelligence: Provider '{provider}' reports reputation status '{rep}'{report_str}."
            )
        elif status == "not_configured":
            reasons.append("Threat Intelligence: No external telephony reputation provider configured (offline static mode).")
        else:
            reasons.append(f"Threat Intelligence: Provider '{provider}' reported status '{status}'.")

    # 4. Contextual Telecom Properties
    if phone_info:
        ntype = phone_info.get("number_type_name", "UNKNOWN").lower()
        region = phone_info.get("region_code", "UNKNOWN")
        cc = phone_info.get("country_code", "")
        reasons.append(f"Contextual Telecom Signals: Type: {ntype}; Origin: {region} (+{cc}).")

    return reasons


def generate_phone_summary(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
) -> str:
    """
    Generate an authoritative, objective summary of the phone scan.
    Adheres strictly to the principle that 'not reported != safe'.
    """
    if risk_level == "unknown":
        return "No strong scam indicators were identified. This does not guarantee that the number is safe."

    rule_ids = {getattr(f, "rule_id", "") for f in findings}
    has_intel_scam = (
        intel_result is not None
        and getattr(intel_result, "status", "") == "available"
        and getattr(intel_result, "reputation", "") == "reported_scam"
    )
    has_premium_rate = "PHONE_RULE_PREMIUM_RATE" in rule_ids
    has_impersonation = "PHONE_RULE_CONTEXT_IMPERSONATION" in rule_ids

    if risk_level == "critical":
        reasons_list = []
        if has_intel_scam:
            reasons_list.append("verified threat intelligence scam reports")
        if has_premium_rate:
            reasons_list.append("premium-rate tariff exploitation (Wangiri fraud)")
        if not reasons_list:
            reasons_list.append("multiple high-severity telephony fraud indicators")
        return f"CRITICAL PHONE THREAT: Number exhibits strong markers of fraudulent activity, including {', '.join(reasons_list)}."

    if risk_level == "high":
        elements = []
        if has_impersonation:
            elements.append("institutional authority impersonation cues")
        if has_premium_rate:
            elements.append("high-tariff callback risks")
        if not elements:
            elements.append("patterns strongly associated with telemarketing or robocall fraud")
        return f"HIGH RISK CALLER: Analysis identified high-risk indicators ({', '.join(elements)})."

    if risk_level == "medium":
        return "Suspicious telephony indicators detected. Patterns suggest potential unverified marketing, spoofing, or irregular digit structuring."

    if risk_level == "low":
        return "Minor observations noted. The number follows standard subscriber formatting with no corroborated abuse reports."

    return "Valid number structure with zero threat indicators detected. (Note: does not guarantee the caller's live identity)."


def generate_phone_recommendation(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
) -> str:
    """
    Generate actionable defensive recommendations for user safety.
    """
    if risk_level in ("critical", "high"):
        rule_ids = {getattr(f, "rule_id", "") for f in findings}
        if "PHONE_RULE_PREMIUM_RATE" in rule_ids:
            return "DO NOT call this number back. Premium-rate international numbers incur steep charges upon connection (Wangiri scam)."
        return "Do NOT share OTPs, banking credentials, UPI PINs, or remote-access codes. Block this number and report it to your telecom carrier or national cyber crime portal."

    if risk_level == "medium":
        return "Exercise caution. Never reveal sensitive personal or financial information during unsolicited incoming calls."

    if risk_level == "unknown":
        return "Remain vigilant. If this caller asks for money, passwords, or immediate action, hang up and verify through their official published website."

    return "Standard telephone precautions apply: legitimate institutions will never ask for your passwords or OTPs over the phone."


# --- Android APK Explainability & Guidance (Phase 07) ---

def generate_apk_reasons(
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
    apk_info: Optional[Dict[str, Any]] = None,
    privacy_result: Optional[Any] = None,
) -> List[str]:
    """
    Generate evidence-based, transparent bulleted reasons for APK analysis.
    Clearly distinguishes observed manifest permissions, static bytecode indicators,
    ML classifier predictions, threat intelligence, and privacy capabilities.
    """
    reasons: List[str] = []

    # 1. Manifest & Heuristic Findings
    if findings:
        for f in findings:
            reasons.append(f"Static Finding: {f.name} — {f.description} ({f.evidence or ''})")
    else:
        reasons.append("Static Finding: No suspicious permission clusters or malicious bytecode patterns identified.")

    # 2. ML Classifier Signals
    if ml_result and ml_result.get("prediction") not in ("unknown", "error", "unavailable"):
        score = ml_result.get("model_score", 0.0)
        pct = int(round(score * 100))
        pred = ml_result.get("prediction", "clean")
        reasons.append(
            f"ML Classifier Evidence: Statistical model estimated a {pct}% probability of structural and "
            f"capability correlation with known Android malware families (Classification: {pred})."
        )

    # 3. Threat Intelligence
    if intel_result:
        status = getattr(intel_result, "status", "not_configured")
        provider = getattr(intel_result, "provider", "unknown")
        rep = getattr(intel_result, "reputation", "unknown")
        fam = getattr(intel_result, "malware_family", None)

        if status == "available":
            fam_str = f" ({fam})" if fam else ""
            reasons.append(f"Threat Intelligence: Provider '{provider}' reports reputation '{rep}'{fam_str}.")
        elif status == "not_configured":
            reasons.append("Threat Intelligence: No external APK hash reputation provider configured (offline static mode).")
        else:
            reasons.append(f"Threat Intelligence: Provider '{provider}' reported status '{status}'.")

    # 4. Privacy Risk & Capability Analysis (Phase 08)
    if privacy_result:
        priv_score = getattr(privacy_result, "privacy_score", 0)
        priv_level = getattr(privacy_result, "privacy_risk_level", "low").upper()
        sens = getattr(privacy_result, "sensitive_permissions_count", 0)
        total = getattr(privacy_result, "total_requested_count", 0)
        high_caps = getattr(privacy_result, "high_impact_capabilities", [])
        high_str = f" including {', '.join(high_caps[:3])}" if high_caps else ""

        reasons.append(
            f"Privacy Capability Audit: Requests {total} permissions ({sens} sensitive{high_str}). "
            f"Evaluated Privacy Risk: {priv_level} ({priv_score}/100)."
        )

        ctx = getattr(privacy_result, "context_analysis", {})
        mismatch = ctx.get("mismatch_level") if isinstance(ctx, dict) else getattr(ctx, "mismatch_level", None)
        if mismatch in ("HIGH", "MEDIUM"):
            expl = ctx.get("explanation") if isinstance(ctx, dict) else getattr(ctx, "explanation", "")
            reasons.append(f"Contextual Capability Mismatch: {expl}")

        # Bytecode API correlation
        corrs = getattr(privacy_result, "api_correlations", [])
        correlated_names = [c.get("permission", "").split(".")[-1] for c in corrs if c.get("status") == "CORRELATED"]
        if correlated_names:
            reasons.append(
                f"Bytecode Correlation: Static inspection verified API references for requested permissions: [{', '.join(correlated_names[:4])}]."
            )

        reasons.append(
            "Static Evidence Boundary: Analysis observes requested capabilities and code references. "
            "It does not demonstrate that permissions were granted or that data was accessed at runtime."
        )

    # 5. Contextual Package Metadata
    if apk_info:
        pkg = apk_info.get("package_name", "")
        tsdk = apk_info.get("target_sdk_version", "")
        perms = apk_info.get("total_permissions", 0)
        reasons.append(f"Contextual Metadata: Package '{pkg}' targets Android SDK {tsdk or 'N/A'} with {perms} declared permissions.")

    return reasons


def generate_apk_summary(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
    privacy_result: Optional[Any] = None,
) -> str:
    """
    Generate an authoritative, objective summary of the APK analysis.
    """
    if risk_level == "unknown":
        return "Insufficient static metadata extracted to establish a confident Android APK risk assessment."

    rule_ids = {getattr(f, "rule_id", "") for f in findings}
    has_banking_overlay = "APK_CLUSTER_BANKING_OVERLAY" in rule_ids
    has_surveillance = "APK_CLUSTER_SURVEILLANCE" in rule_ids
    has_dropper = "APK_CLUSTER_DROPPER" in rule_ids
    has_shell = "APK_RULE_SHELL_EXECUTION" in rule_ids
    has_intel_malware = (
        intel_result is not None
        and getattr(intel_result, "status", "") == "available"
        and getattr(intel_result, "reputation", "") == "known_malware"
    )

    if risk_level == "critical":
        elements = []
        if has_banking_overlay:
            elements.append("Accessibility service abuse and System Alert Window overlay capabilities")
        if has_intel_malware:
            elements.append("verified threat intelligence hash detection")
        if has_shell:
            elements.append("root shell command execution invocations")
        if not elements:
            elements.append("critical permission clusters and high-risk bytecode APIs")
        return f"CRITICAL MALWARE THREAT: APK demonstrates aggressive indicators typical of Android Banking Trojans or Advanced Spyware, including {', '.join(elements)}."

    if risk_level == "high":
        elements = []
        if has_surveillance:
            elements.append("surveillance sensors (audio, camera, location)")
        if has_dropper:
            elements.append("unverified package installation capabilities")
        if not elements:
            elements.append("high-privilege capability requests and reflection indicators")
        return f"HIGH RISK APPLICATION: Suspicious capabilities detected ({', '.join(elements)}), warranting immediate security review."

    if risk_level == "medium":
        priv_extra = ""
        if privacy_result and getattr(privacy_result, "privacy_risk_level", "") in ("high", "critical"):
            priv_extra = f" Elevated privacy footprint ({getattr(privacy_result, 'privacy_score', 0)}/100) noted."
        return f"Moderate security observations noted. Application declares sensitive permissions or dynamic loading routines that exceed standard utility scope.{priv_extra}"

    if risk_level == "low":
        return "Minor observations noted. The package structure and requested permissions conform to standard Android development practices."

    return "Clean application structure. Zero suspicious permission clusters, shell execution, or overlay capabilities detected."


def generate_apk_recommendation(
    risk_level: str,
    findings: List[Any],
    ml_result: Optional[Dict[str, Any]] = None,
    intel_result: Optional[Any] = None,
    privacy_result: Optional[Any] = None,
) -> str:
    """
    Generate defensive security guidance for Android application handling.
    """
    rule_ids = {getattr(f, "rule_id", "") for f in findings}

    if risk_level in ("critical", "high"):
        if "APK_CLUSTER_BANKING_OVERLAY" in rule_ids:
            return "DO NOT install or launch this application. If already installed, immediately revoke Accessibility permissions, disconnect from network, and uninstall."
        if "APK_CLUSTER_DEVICE_ADMIN" in rule_ids:
            return "DO NOT grant Device Administrator privileges. If active, deactivate under Device Settings -> Security -> Device Admin Apps before uninstalling."
        return "DO NOT install this APK. Only install applications from verified official sources such as the Google Play Store."

    if risk_level == "medium":
        if privacy_result and getattr(privacy_result, "recommendation", ""):
            return f"Exercise caution. {getattr(privacy_result, 'recommendation', '')}"
        return "Exercise caution. Review requested permissions in device settings and deny any capabilities that do not match the application's stated purpose."

    if risk_level == "unknown":
        return "Proceed with caution. Exercise standard mobile hygiene and verify the APK's publisher and certificate before installation."

    return "Standard Android security practices apply: verify developers and install updates only through verified application stores."




