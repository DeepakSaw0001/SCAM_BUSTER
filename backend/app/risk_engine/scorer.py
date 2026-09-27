"""
ScamBuster Risk Engine — Scorer

Calculates provisional risk score (0-100), calibrated risk level,
and analytical confidence score based on static rule findings.

NOTE ON SCORING SCALE:
The 0-100 scale and risk tiers:
- 0–19:   Very Low (very_low)
- 20–39:  Low (low)
- 40–59:  Medium (medium)
- 60–79:  High (high)
- 80–100: Critical (critical)
are provisional heuristic thresholds designed for initial rule correlation.
They are NOT yet scientifically validated statistical thresholds.
The scoring system is architected so weights and thresholds can be calibrated
using empirical validation datasets in future ML phases.
"""

from typing import Any, List, Optional, Tuple
from app.services.url_rule_detector import RuleFinding

MODEL_VERSION = "rules-v1"


def calculate_risk_score(
    findings: List[RuleFinding],
    has_sufficient_evidence: bool = True
) -> Tuple[int, str, float]:
    """
    Calculate provisional risk score, risk level, and analytical confidence.

    Returns:
        (risk_score: int [0-100], risk_level: str, confidence: float [0.0-1.0])
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0

    if not findings:
        # Clean baseline with no detected indicators
        # High confidence in low risk for standard domain structures
        return 0, "very_low", 0.85

    # Sum weighted findings with diminishing returns to avoid artificial 100s
    raw_score = sum(f.score_weight for f in findings)
    severities = [f.severity for f in findings]

    # Calculate composite score based on accumulation and severity spikes
    has_critical = "critical" in severities
    high_count = severities.count("high")
    medium_count = severities.count("medium")

    if has_critical or high_count >= 2:
        # Multiple strong indicators
        score = min(max(raw_score, 80), 100)
    elif high_count == 1 and medium_count >= 1:
        # One strong plus auxiliary indicators
        score = min(max(raw_score, 65), 79)
    elif high_count == 1:
        # Single high indicator
        score = min(raw_score, 59)
    elif medium_count >= 2:
        score = min(raw_score, 55)
    else:
        # Low severity indicators (e.g. HTTP only or single keyword)
        score = min(raw_score, 35)

    # Determine provisional risk tier
    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Confidence calculation:
    # Based on evidence corroboration (not fabricated AI confidence):
    # Single indicator = 0.60
    # Two indicators = 0.72
    # Three+ indicators = 0.82 to 0.88
    indicator_count = len(findings)
    if indicator_count == 1:
        confidence = 0.62
    elif indicator_count == 2:
        confidence = 0.75
    elif indicator_count == 3:
        confidence = 0.82
    else:
        confidence = min(0.85 + (indicator_count * 0.02), 0.94)

    return score, level, round(confidence, 2)


def _process_threat_intelligence_signals(
    threat_intel: Optional[Any]
) -> Tuple[bool, bool, bool, int, float, List[str]]:
    """
    Extracts high-level signals from a CorrelatedIntelligenceResult, dict of results, or raw report dicts.
    Returns:
        (has_malicious, is_corroborated, is_conflicting, malicious_count, highest_confidence, categories)
    """
    if not threat_intel:
        return False, False, False, 0, 0.0, []

    items = []
    if isinstance(threat_intel, dict):
        if "aggregate_verdict" in threat_intel or "verdict" in threat_intel:
            items.append(threat_intel)
        else:
            items.extend(threat_intel.values())
    elif isinstance(threat_intel, list):
        items.extend(threat_intel)
    else:
        items.append(threat_intel)

    has_malicious = False
    is_corroborated = False
    is_conflicting = False
    malicious_count = 0
    highest_conf = 0.0
    all_categories: set[str] = set()

    for item in items:
        # Check verdict on dataclass or dict
        raw_verdict = getattr(item, "aggregate_verdict", None) or getattr(item, "verdict", None)
        if raw_verdict is None and isinstance(item, dict):
            raw_verdict = item.get("aggregate_verdict") or item.get("verdict")
        verdict = str(raw_verdict or "").lower()

        if "malicious" in verdict:
            has_malicious = True
            malicious_count += 1

        raw_conf = getattr(item, "aggregate_confidence", None) or getattr(item, "confidence", None)
        if raw_conf is None and isinstance(item, dict):
            raw_conf = item.get("aggregate_confidence") or item.get("confidence", 0.0)
        try:
            conf = float(raw_conf or 0.0)
            highest_conf = max(highest_conf, conf)
        except (ValueError, TypeError):
            pass

        if getattr(item, "is_corroborated", False) or (isinstance(item, dict) and item.get("is_corroborated", False)):
            is_corroborated = True
        if getattr(item, "is_conflicting", False) or (isinstance(item, dict) and item.get("is_conflicting", False)):
            is_conflicting = True

        cats = getattr(item, "categories", []) or (item.get("categories", []) if isinstance(item, dict) else [])
        for c in cats:
            if isinstance(c, str):
                all_categories.add(c)

    return has_malicious, is_corroborated, is_conflicting, malicious_count, highest_conf, sorted(list(all_categories))


def calculate_unified_url_risk(
    rule_findings: List[RuleFinding],
    ml_result: Optional[dict] = None,
    has_sufficient_evidence: bool = True,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int]:
    """
    Fuse static rule findings with machine learning prediction and external threat intelligence
    into a unified risk assessment.

    Design & Weighting Architecture:
    - Rule Score (R): 0 - 100 based on explicit heuristic & signature indicators.
    - ML Score (M): 0 - 100 based on RandomForest predicted malicious probability.
    - Threat Intelligence: Corroborated or single-source external reputation evidence.
    - Fusion Weighting (Provisional): Composite = round(0.55 * R + 0.45 * M).
    - Defense-in-Depth Guardrail 1: High severity rule findings (R >= 80) keep composite >= 75.
    - Defense-in-Depth Guardrail 2: Strong ML threat signal (M >= 85) with non-zero rules elevates composite >= 70.
    - Defense-in-Depth Guardrail 3: Corroborated threat intelligence elevates composite >= 85, confidence >= 0.96.
    - Clean Baseline Guardrail: Clean rules (R == 0) and low ML (M <= 10) keep composite <= 5.

    Returns:
        (composite_score, composite_level, unified_confidence, rule_score, ml_score)
    """
    rule_score, rule_level, rule_conf = calculate_risk_score(
        rule_findings, has_sufficient_evidence=has_sufficient_evidence
    )

    if not ml_result or not ml_result.get("available", False):
        # Fallback to pure rule score if ML is offline/unavailable
        raw_composite = float(rule_score)
        ml_score = 0
    else:
        ml_prob = float(ml_result.get("model_probability", 0.0))
        ml_score = int(round(ml_prob * 100))
        raw_composite = (0.55 * rule_score) + (0.45 * ml_score)

    composite_score = int(round(raw_composite))

    # Apply defense-in-depth security guardrails
    if rule_score >= 80:
        composite_score = max(composite_score, 75)
    elif ml_score >= 85 and rule_score >= 20:
        composite_score = max(composite_score, 70)
    elif rule_score == 0 and ml_score <= 10 and not threat_intelligence:
        composite_score = min(composite_score, 5)

    # Threat Intelligence Evidence Integration
    has_mal, is_corr, is_conflict, mal_cnt, intel_conf, _ = _process_threat_intelligence_signals(threat_intelligence)
    if has_mal:
        if is_corr:
            composite_score = max(composite_score, 85)
        elif is_conflict:
            composite_score = max(composite_score, 65)
        else:
            composite_score = max(composite_score, 72)

    composite_score = min(max(composite_score, 0), 100)

    # Calibrate risk tier
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Agreement-based analytical confidence
    rule_is_threat = rule_score >= 40
    ml_is_threat = ml_score >= 50

    if has_mal and is_corr:
        confidence = 0.96
    elif has_mal and is_conflict:
        confidence = 0.70
    elif rule_is_threat == ml_is_threat:
        # Concordant signals
        if composite_score >= 70 or composite_score <= 15:
            confidence = 0.92
        else:
            confidence = 0.85
    else:
        # Divergent signals (e.g. heuristics found keyword, ML structural model sees standard path)
        confidence = 0.68

    return composite_score, level, confidence, rule_score, ml_score


def calculate_message_rule_score(
    findings: List[Any],
    has_sufficient_evidence: bool = True
) -> Tuple[int, str, float]:
    """
    Calculate provisional rule-based risk score (0-100), risk tier, and analytical confidence
    specifically for SMS / text message heuristics.
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0

    if not findings:
        return 0, "very_low", 0.85

    raw_score = sum(getattr(f, "score_weight", 0) for f in findings)
    severities = [getattr(f, "severity", "").lower() for f in findings]

    has_critical = "critical" in severities
    high_count = severities.count("high")
    medium_count = severities.count("medium")

    if has_critical:
        score = min(max(raw_score, 80), 100)
    elif high_count >= 2:
        score = min(max(raw_score, 75), 100)
    elif high_count == 1 and medium_count >= 1:
        score = min(max(raw_score, 65), 79)
    elif high_count == 1:
        score = min(max(raw_score, 50), 65)
    elif medium_count >= 2:
        score = min(raw_score, 55)
    else:
        score = min(raw_score, 35)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "very_low"

    count = len(findings)
    if count == 1:
        conf = 0.65
    elif count == 2:
        conf = 0.78
    elif count >= 3:
        conf = min(0.85 + (count * 0.02), 0.95)
    else:
        conf = 0.85

    return score, level, round(conf, 2)


def calculate_unified_message_risk(
    rule_findings: List[Any],
    ml_result: Optional[dict] = None,
    embedded_urls_analysis: Optional[List[dict]] = None,
    has_sufficient_evidence: bool = True,
    social_engineering_findings: Optional[List[Any]] = None,
    phone_analysis: Optional[List[dict]] = None,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int]:
    """
    Fuse static message rule findings, NLP ML classification, embedded URL static scans,
    phone number correlation, social engineering indicators, and external threat intelligence
    into a unified composite risk assessment.

    Weighting & Defense-in-Depth Architecture:
    - Rule Score (R): 0 - 100 based on heuristic message & social engineering findings.
    - ML Score (M): 0 - 100 based on Calibrated LinearSVC predicted scam probability.
    - Multi-Signal Corroboration:
      Evaluates independent signal vectors (NLP manipulation, Identity/Sender, Deceptive structure,
      Embedded URLs, Telecom/Phone risk, ML, and Threat Intelligence).
      When 2+ independent vectors flag risk, elevates threat floor.
    - Deduplication:
      Prevents double-counting the same underlying fact across rule categories.
    - Clean baseline (R=0, M<=10, no malicious URLs/phones/threat intel) -> composite <= 5.

    Returns:
        (composite_score, composite_level, unified_confidence, rule_score, ml_score)
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0, 0, 0

    all_rule_findings = list(rule_findings)
    if social_engineering_findings:
        seen_concepts = {getattr(f, "rule_id", "") for f in all_rule_findings}
        for se in social_engineering_findings:
            se_id = getattr(se, "rule_id", "")
            if se_id not in seen_concepts:
                all_rule_findings.append(se)
                seen_concepts.add(se_id)

    rule_score, rule_level, rule_conf = calculate_message_rule_score(
        all_rule_findings, has_sufficient_evidence=has_sufficient_evidence
    )

    if not ml_result or not ml_result.get("available", False):
        ml_score = 0
        raw_composite = float(rule_score)
    else:
        ml_prob = float(ml_result.get("model_probability", 0.0))
        ml_score = int(round(ml_prob * 100))
        raw_composite = (0.50 * rule_score) + (0.50 * ml_score)

    composite_score = int(round(raw_composite))

    # Defense-in-Depth Guardrails
    severities = [getattr(f, "severity", "").lower() for f in all_rule_findings]
    rule_ids = {getattr(f, "rule_id", "") for f in all_rule_findings}

    if "critical" in severities or "RULE_SE_OTP_HARVEST" in rule_ids or "RULE_SE_ANCHOR_MISMATCH" in rule_ids:
        composite_score = max(composite_score, 82)
    elif ml_score >= 85 and rule_score >= 20:
        composite_score = max(composite_score, 75)

    # Corroborate with embedded URL analysis if present
    highest_url_score = 0
    if embedded_urls_analysis:
        highest_url_score = max((u.get("risk_score", 0) for u in embedded_urls_analysis), default=0)
        if highest_url_score >= 80:
            composite_score = max(composite_score, 82)
        elif highest_url_score >= 60:
            composite_score = max(composite_score, 68)

    # Corroborate with phone number analysis if present
    highest_phone_score = 0
    if phone_analysis:
        highest_phone_score = max((p.get("score", p.get("risk_score", 0)) for p in phone_analysis), default=0)
        if highest_phone_score >= 80:
            composite_score = max(composite_score, 75)
        elif highest_phone_score >= 60:
            composite_score = max(composite_score, 65)

    # Multi-Signal Corroboration Engine
    vectors_active = set()
    if any(r in rule_ids for r in ["RULE_SE_OTP_HARVEST", "RULE_SE_CREDENTIAL_HARVEST", "RULE_CREDENTIAL_SOLICITATION"]):
        vectors_active.add("credential_harvesting")
    if any(r in rule_ids for r in ["RULE_SE_URGENCY_MANIPULATION", "RULE_URGENCY_PRESSURE"]):
        vectors_active.add("urgency")
    if any(r in rule_ids for r in ["RULE_SE_FEAR_COERCION", "RULE_THREAT_COERCION"]):
        vectors_active.add("intimidation")
    if any(r in rule_ids for r in ["RULE_SE_REWARD_BAIT", "RULE_UNSOLICITED_REWARD", "RULE_SE_PAYMENT_REQUEST"]):
        vectors_active.add("financial_lure")
    if any(r in rule_ids for r in ["RULE_SE_BRAND_LOOKALIKE", "RULE_SE_BRAND_DOMAIN_MISMATCH"]):
        vectors_active.add("brand_impersonation")
    if highest_url_score >= 60 or "RULE_SE_ANCHOR_MISMATCH" in rule_ids:
        vectors_active.add("malicious_url")
    if highest_phone_score >= 60:
        vectors_active.add("suspicious_phone")
    if ml_score >= 60:
        vectors_active.add("ml_threat")

    # Threat Intelligence Signals
    has_mal, is_corr, is_conflict, mal_cnt, intel_conf, _ = _process_threat_intelligence_signals(threat_intelligence)
    if has_mal:
        vectors_active.add("threat_intelligence")
        if is_corr:
            composite_score = max(composite_score, 85)
        elif is_conflict:
            composite_score = max(composite_score, 65)
        else:
            composite_score = max(composite_score, 72)

    if len(vectors_active) >= 3:
        composite_score = max(composite_score, 82)
    elif len(vectors_active) >= 2:
        composite_score = max(composite_score, 72)

    if rule_score == 0 and ml_score <= 10 and not any((u.get("risk_score", 0) >= 40) for u in (embedded_urls_analysis or [])) and not any((p.get("score", 0) >= 40) for p in (phone_analysis or [])) and not has_mal:
        composite_score = min(composite_score, 5)

    composite_score = min(max(composite_score, 0), 100)

    # Determine risk level
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Agreement-based analytical confidence
    rule_is_threat = rule_score >= 40
    ml_is_threat = ml_score >= 50

    if has_mal and is_corr:
        confidence = 0.96
    elif has_mal and is_conflict:
        confidence = 0.70
    elif len(vectors_active) >= 3:
        confidence = 0.95
    elif len(vectors_active) >= 2 or (rule_is_threat == ml_is_threat):
        confidence = 0.92 if (composite_score >= 70 or composite_score <= 15) else 0.85
    else:
        confidence = 0.72

    return composite_score, level, confidence, rule_score, ml_score


def calculate_email_rule_score(
    findings: List[Any],
    has_sufficient_evidence: bool = True
) -> Tuple[int, str, float]:
    """
    Calculate provisional rule-based risk score (0-100), risk tier, and analytical confidence
    specifically for Email heuristics (From/Reply-To mismatch, Auth failures, Anchor mismatches, Attachments).
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0

    if not findings:
        return 0, "very_low", 0.88

    raw_score = sum(getattr(f, "score_weight", 0) for f in findings)
    severities = [getattr(f, "severity", "").lower() for f in findings]

    has_critical = "critical" in severities
    high_count = severities.count("high")
    medium_count = severities.count("medium")

    if has_critical:
        score = min(max(raw_score, 80), 100)
    elif high_count >= 2:
        score = min(max(raw_score, 75), 100)
    elif high_count == 1 and medium_count >= 1:
        score = min(max(raw_score, 65), 79)
    elif high_count == 1:
        score = min(max(raw_score, 50), 65)
    elif medium_count >= 2:
        score = min(raw_score, 55)
    else:
        score = min(raw_score, 35)

    if score >= 80:
        level = "critical"
    elif score >= 60:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score >= 20:
        level = "low"
    else:
        level = "very_low"

    count = len(findings)
    if count == 1:
        conf = 0.70
    elif count == 2:
        conf = 0.82
    elif count >= 3:
        conf = min(0.88 + (count * 0.02), 0.96)
    else:
        conf = 0.88

    return score, level, round(conf, 2)


def calculate_unified_email_risk(
    rule_findings: List[Any],
    ml_result: Optional[dict] = None,
    embedded_urls_analysis: Optional[List[dict]] = None,
    has_sufficient_evidence: bool = True,
    social_engineering_findings: Optional[List[Any]] = None,
    phone_analysis: Optional[List[dict]] = None,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int]:
    """
    Fuse static email rule findings, NLP ML classification, embedded URL static scans,
    phone correlation, social engineering rules, attachment risk signatures, and external threat intelligence
    into a unified composite risk assessment.

    Deduplication & Defense-in-Depth:
    - Avoids double-counting repeated links or overlapping rule penalties.
    - Critical findings (e.g. anchor text mismatch, dangerous executable attachment, or corroborated threat intel)
      elevate threat floor to >= 82 (Critical).
    - Multi-signal corroboration boosts confidence and risk floor when distinct threat vectors agree.
    - Clean emails with zero findings and low ML score result in <= 5 (Very Low).

    Returns:
        (composite_score, composite_level, unified_confidence, rule_score, ml_score)
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0, 0, 0

    all_rule_findings = list(rule_findings)
    if social_engineering_findings:
        seen_concepts = {getattr(f, "rule_id", "") for f in all_rule_findings}
        for se in social_engineering_findings:
            se_id = getattr(se, "rule_id", "")
            if se_id not in seen_concepts:
                all_rule_findings.append(se)
                seen_concepts.add(se_id)

    rule_score, rule_level, rule_conf = calculate_email_rule_score(
        all_rule_findings, has_sufficient_evidence=has_sufficient_evidence
    )

    if not ml_result or not ml_result.get("available", False):
        ml_score = 0
        raw_composite = float(rule_score)
    else:
        ml_prob = float(ml_result.get("model_probability", 0.0))
        ml_score = int(round(ml_prob * 100))
        # 50/50 fusion of heuristic security evidence and statistical NLP signal
        raw_composite = (0.50 * rule_score) + (0.50 * ml_score)

    composite_score = int(round(raw_composite))

    # Guardrails: Critical security findings
    severities = [getattr(f, "severity", "").lower() for f in all_rule_findings]
    rule_ids = {getattr(f, "rule_id", "") for f in all_rule_findings}

    if "critical" in severities or "RULE_SE_DANGEROUS_ATTACHMENT" in rule_ids or "RULE_SE_ANCHOR_MISMATCH" in rule_ids or "RULE_EMAIL_ANCHOR_MISMATCH" in rule_ids:
        composite_score = max(composite_score, 82)
    elif "RULE_EMAIL_SUSPICIOUS_ATTACHMENT" in rule_ids or "RULE_SE_APK_ATTACHMENT" in rule_ids:
        composite_score = max(composite_score, 75)
    elif ("RULE_EMAIL_SENDER_REPLYTO_MISMATCH" in rule_ids or "RULE_SE_REPLY_TO_DIVERGENCE" in rule_ids) and ml_score >= 60:
        composite_score = max(composite_score, 75)
    elif ("RULE_EMAIL_AUTH_FAILURE" in rule_ids or "RULE_SE_AUTH_FAILURE" in rule_ids) and ("RULE_EMAIL_CREDENTIAL_SOLICITATION" in rule_ids or ml_score >= 50):
        composite_score = max(composite_score, 76)
    elif ml_score >= 85 and rule_score >= 20:
        composite_score = max(composite_score, 72)

    # Corroborate with embedded URL analysis (deduplicated maximum risk)
    highest_url_score = 0
    if embedded_urls_analysis:
        highest_url_score = max((u.get("risk_score", 0) for u in embedded_urls_analysis), default=0)
        if highest_url_score >= 80:
            composite_score = max(composite_score, 82)
        elif highest_url_score >= 60:
            composite_score = max(composite_score, 68)

    # Multi-Signal Corroboration Engine for Email:
    vectors_active = set()
    if any(r in rule_ids for r in ["RULE_EMAIL_CREDENTIAL_SOLICITATION", "RULE_SE_CREDENTIAL_HARVEST", "RULE_SE_OTP_HARVEST"]):
        vectors_active.add("credential_harvesting")
    if any(r in rule_ids for r in ["RULE_EMAIL_URGENCY_THREAT", "RULE_SE_URGENCY_MANIPULATION"]):
        vectors_active.add("urgency")
    if any(r in rule_ids for r in ["RULE_EMAIL_SENDER_REPLYTO_MISMATCH", "RULE_SE_REPLY_TO_DIVERGENCE", "RULE_SE_BRAND_LOOKALIKE", "RULE_SE_BRAND_DOMAIN_MISMATCH", "RULE_EMAIL_AUTH_FAILURE"]):
        vectors_active.add("sender_spoofing")
    if any(r in rule_ids for r in ["RULE_EMAIL_ANCHOR_MISMATCH", "RULE_SE_ANCHOR_MISMATCH"]) or highest_url_score >= 60:
        vectors_active.add("deceptive_links")
    if any(r in rule_ids for r in ["RULE_EMAIL_SUSPICIOUS_ATTACHMENT", "RULE_SE_DANGEROUS_ATTACHMENT", "RULE_SE_APK_ATTACHMENT", "RULE_EMAIL_DOUBLE_EXTENSION_ATTACHMENT"]):
        vectors_active.add("suspicious_attachment")
    if ml_score >= 60:
        vectors_active.add("ml_threat")

    # Threat Intelligence Signals
    has_mal, is_corr, is_conflict, mal_cnt, intel_conf, _ = _process_threat_intelligence_signals(threat_intelligence)
    if has_mal:
        vectors_active.add("threat_intelligence")
        if is_corr:
            composite_score = max(composite_score, 85)
        elif is_conflict:
            composite_score = max(composite_score, 65)
        else:
            composite_score = max(composite_score, 72)

    if len(vectors_active) >= 3:
        composite_score = max(composite_score, 82)
    elif len(vectors_active) >= 2:
        composite_score = max(composite_score, 72)

    # Clean baseline
    if rule_score == 0 and ml_score <= 15 and not any((u.get("risk_score", 0) >= 40) for u in (embedded_urls_analysis or [])) and not has_mal:
        composite_score = min(composite_score, 5)

    composite_score = min(max(composite_score, 0), 100)

    # Determine risk level
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    if has_mal and is_corr:
        confidence = 0.96
    elif has_mal and is_conflict:
        confidence = 0.70
    elif len(vectors_active) >= 3:
        confidence = 0.96
    elif len(vectors_active) >= 2:
        confidence = 0.92
    else:
        confidence = 0.88 if (composite_score <= 10 or composite_score >= 70) else 0.78

    return composite_score, level, confidence, rule_score, ml_score


def calculate_unified_phone_risk(
    rule_score: int,
    findings: List[Any],
    ml_result: Optional[dict] = None,
    intel_result: Optional[Any] = None,
    has_sufficient_evidence: bool = True,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int, int]:
    """
    Fuse static telephony heuristics, ML digit-pattern probability, and external
    threat intelligence into a calibrated composite risk assessment.

    Design Principles:
    - Zero fake intelligence: absence of reports != safe.
    - If no threat indicators are detected and intelligence is not configured/unreported,
      returns 'unknown' risk level to avoid falsely declaring an unverified number safe.
    - Prevents double-counting between intelligence reports and rule indicators.
    - Never flags standard VoIP or mobile numbers as malicious by themselves.

    Returns:
        (composite_score, risk_level, confidence, rule_score, ml_score, intel_score)
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0, 0, 0, 0

    # ML Score extraction
    if not ml_result or ml_result.get("prediction") in ("unknown", "error", "unavailable"):
        ml_score = 0
        ml_available = False
    else:
        ml_prob = float(ml_result.get("model_score", 0.0))
        ml_score = int(round(ml_prob * 100))
        ml_available = True

    # Threat Intelligence extraction
    has_mal, is_corr, is_conflict, mal_cnt, _, _ = _process_threat_intelligence_signals(threat_intelligence)

    intel_status = getattr(intel_result, "status", "not_configured") if intel_result else "not_configured"
    intel_rep = getattr(intel_result, "reputation", "unknown") if intel_result else "unknown"

    if has_mal:
        intel_available = True
        intel_score = 92 if is_corr else 80
        intel_rep = "reported_scam"
    elif intel_result and intel_status == "available":
        intel_available = True
        if intel_rep == "reported_scam":
            intel_score = 90
        elif intel_rep == "suspicious":
            intel_score = 60
        elif intel_rep == "neutral":
            intel_score = 10
        else:
            intel_score = 0
    else:
        intel_available = False
        intel_score = 0

    # Check for UNKNOWN state:
    # If no rule indicators, no intelligence available/unreported, and ML score is low
    if len(findings) == 0 and not intel_available and ml_score < 35:
        return 10, "unknown", 0.15, rule_score, ml_score, intel_score

    # Weighted composite calculation
    if intel_available:
        # Balanced 3-way fusion
        raw_composite = (0.35 * rule_score) + (0.35 * ml_score) + (0.30 * intel_score)
    elif ml_available:
        # 50/50 rules + ML
        raw_composite = (0.50 * rule_score) + (0.50 * ml_score)
    else:
        raw_composite = float(rule_score)

    composite_score = int(round(raw_composite))

    # Guardrails: high-confidence threat signatures
    severities = [getattr(f, "severity", "").lower() for f in findings]
    rule_ids = {getattr(f, "rule_id", "") for f in findings}

    if intel_available and intel_rep == "reported_scam":
        composite_score = max(composite_score, 82)
    elif "critical" in severities:
        composite_score = max(composite_score, 80)
    elif "PHONE_RULE_PREMIUM_RATE" in rule_ids or "PHONE_RULE_WANGIRI_PREFIX" in rule_ids:
        if "PHONE_RULE_CONTEXT_IMPERSONATION" in rule_ids:
            composite_score = max(composite_score, 72)
        else:
            composite_score = max(composite_score, 65)
    elif "PHONE_RULE_CONTEXT_IMPERSONATION" in rule_ids:
        composite_score = max(composite_score, 55)
    elif ml_score >= 85 and rule_score >= 20:
        composite_score = max(composite_score, 70)

    composite_score = min(max(composite_score, 0), 100)

    # Risk level categorization
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Confidence calculation
    if has_mal and is_corr:
        confidence = 0.96
    elif intel_available:
        confidence = 0.92 if composite_score >= 70 else 0.85
    elif ml_available and len(findings) > 0:
        confidence = 0.82
    elif len(findings) > 0:
        confidence = 0.75
    else:
        confidence = 0.40

    return composite_score, level, confidence, rule_score, ml_score, intel_score


def calculate_unified_apk_risk(
    rule_score: int,
    findings: List[Any],
    ml_result: Optional[dict] = None,
    intel_result: Optional[Any] = None,
    has_sufficient_evidence: bool = True,
    privacy_result: Optional[Any] = None,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int, int]:
    """
    Fuse static APK manifest heuristics, bytecode API signatures, machine learning classification,
    external threat intelligence, and privacy risk analysis into a unified APK security risk assessment.

    Deduplication & Defense-in-Depth:
    - Avoids artificial risk inflation by cross-correlating permission clusters with bytecode indicators.
    - Privacy findings represent capability exposure and context alignment, NOT malware probability.
    - Critical signatures (e.g. Banking Trojan Overlay + SMS interception, or known malware hash)
      elevate composite risk floor to >= 82 (Critical).
    - Dropper, Spyware, or Device Administrator indicators elevate floor to >= 70 (High).
    - Clean benign APKs with zero findings and low ML score result in <= 5 (Very Low).

    Returns:
        (composite_score, risk_level, confidence, rule_score, ml_score, intel_score)
    """
    if not has_sufficient_evidence:
        return 0, "unknown", 0.0, 0, 0, 0

    # ML Score extraction
    if not ml_result or ml_result.get("prediction") in ("unknown", "error", "unavailable"):
        ml_score = 0
        ml_available = False
    else:
        ml_prob = float(ml_result.get("model_score", 0.0))
        ml_score = int(round(ml_prob * 100))
        ml_available = True

    # Threat Intelligence extraction
    has_mal, is_corr, is_conflict, mal_cnt, _, _ = _process_threat_intelligence_signals(threat_intelligence)

    intel_status = getattr(intel_result, "status", "not_configured") if intel_result else "not_configured"
    intel_rep = getattr(intel_result, "reputation", "unknown") if intel_result else "unknown"

    if has_mal:
        intel_available = True
        intel_score = 95
        intel_rep = "known_malware"
    elif intel_result and intel_status == "available":
        intel_available = True
        if intel_rep == "known_malware":
            intel_score = 95
        elif intel_rep == "suspicious":
            intel_score = 65
        elif intel_rep == "clean":
            intel_score = 5
        else:
            intel_score = 0
    else:
        intel_available = False
        intel_score = 0

    # Balanced multi-signal fusion
    if intel_available:
        raw_composite = (0.40 * rule_score) + (0.35 * ml_score) + (0.25 * intel_score)
    elif ml_available:
        raw_composite = (0.50 * rule_score) + (0.50 * ml_score)
    else:
        raw_composite = float(rule_score)

    composite_score = int(round(raw_composite))

    # Guardrails: High-severity malware signatures
    severities = [getattr(f, "severity", "").lower() for f in findings]
    rule_ids = {getattr(f, "rule_id", "") for f in findings}

    if intel_available and intel_rep == "known_malware":
        composite_score = max(composite_score, 88)
    elif "critical" in severities or "APK_CLUSTER_BANKING_OVERLAY" in rule_ids:
        composite_score = max(composite_score, 82)
    elif "APK_CLUSTER_OVERLAY_SMS" in rule_ids or "APK_CLUSTER_SURVEILLANCE" in rule_ids:
        composite_score = max(composite_score, 72)
    elif "APK_CLUSTER_DEVICE_ADMIN" in rule_ids:
        composite_score = max(composite_score, 68)
    elif "APK_RULE_SHELL_EXECUTION" in rule_ids and ml_score >= 50:
        composite_score = max(composite_score, 70)
    elif ml_score >= 85 and rule_score >= 20:
        composite_score = max(composite_score, 75)

    # Privacy contextual guardrail: High privacy risk with severe mismatch elevates floor to Medium
    if privacy_result:
        priv_score = getattr(privacy_result, "privacy_score", 0)
        ctx = getattr(privacy_result, "context_analysis", {})
        mismatch = ctx.get("mismatch_level", "NONE") if isinstance(ctx, dict) else getattr(ctx, "mismatch_level", "NONE")
        if priv_score >= 75 and mismatch == "HIGH" and composite_score < 45:
            composite_score = 45

    # Clean baseline
    if rule_score == 0 and ml_score <= 15 and not intel_available and not has_mal:
        composite_score = min(composite_score, 5)

    composite_score = min(max(composite_score, 0), 100)

    # Determine risk level
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Analytical confidence
    if has_mal and is_corr:
        confidence = 0.98
    elif intel_available:
        confidence = 0.95 if composite_score >= 70 else 0.88
    elif ml_available and len(findings) > 0:
        confidence = 0.90
    elif len(findings) > 0:
        confidence = 0.80
    else:
        confidence = 0.85

    return composite_score, level, confidence, rule_score, ml_score, intel_score


def calculate_unified_url_and_web_risk(
    url_findings: List[Any],
    url_ml_result: Optional[dict] = None,
    web_findings: Optional[List[dict]] = None,
    web_ml_result: Optional[dict] = None,
    download_analysis: Optional[dict] = None,
    has_sufficient_evidence: bool = True,
    threat_intelligence: Optional[Any] = None,
) -> Tuple[int, str, float, int, int, int]:
    """
    Phase 09 & 11: Fuse static lexical URL analysis with live safe web fetch,
    redirect chain tracking, HTML content inspection, download analysis, Web ML,
    and correlated threat intelligence.

    Returns:
        (composite_score, risk_level, confidence, url_lexical_score, web_rule_score, ml_score)
    """
    web_findings = web_findings or []
    
    # 1. Lexical URL score
    lex_score, lex_level, lex_conf = calculate_risk_score(url_findings, has_sufficient_evidence)
    
    # 2. Web Rule score
    from app.services.web_risk_rules import evaluate_web_risk_rules
    web_rule_score = 0
    severities = [f.get("severity", "").lower() for f in web_findings]
    if "critical" in severities:
        web_rule_score = 85
    elif severities.count("high") >= 2:
        web_rule_score = 75
    elif severities.count("high") == 1:
        web_rule_score = 55
    elif severities.count("medium") >= 2:
        web_rule_score = 45
    elif severities.count("medium") == 1:
        web_rule_score = 30
    elif len(web_findings) > 0:
        web_rule_score = 15

    # 3. ML Scores
    url_ml_prob = float(url_ml_result.get("model_probability", 0.0)) if url_ml_result and url_ml_result.get("available") else 0.0
    web_ml_prob = float(web_ml_result.get("model_score", 0.0)) if web_ml_result and web_ml_result.get("available") else 0.0
    
    has_url_ml = bool(url_ml_result and url_ml_result.get("available"))
    has_web_ml = bool(web_ml_result and web_ml_result.get("available"))
    
    if has_url_ml and has_web_ml:
        combined_ml_prob = (0.45 * url_ml_prob) + (0.55 * web_ml_prob)
    elif has_web_ml:
        combined_ml_prob = web_ml_prob
    else:
        combined_ml_prob = url_ml_prob
        
    ml_score = int(round(combined_ml_prob * 100))

    # 4. APK / Download Signal Integration
    apk_bonus = 0
    if download_analysis and download_analysis.get("is_apk"):
        apk_res = download_analysis.get("apk_analysis") or {}
        apk_rule = apk_res.get("rule_risk_score", 0)
        apk_priv = apk_res.get("privacy_risk_score", 0)
        apk_bonus = int(max(apk_rule, apk_priv) * 0.3)

    # 5. Composite Fusion (Lexical: 25%, Web Rules: 45%, ML: 30%)
    raw_composite = (0.25 * lex_score) + (0.45 * web_rule_score) + (0.30 * ml_score) + apk_bonus

    # 6. Defense-in-Depth Guardrails
    rule_ids = {f.get("rule_id") for f in web_findings}
    
    if "WEB_RULE_SSRF_BLOCKED" in rule_ids:
        composite_score = 90
    elif "WEB_RULE_DOWNLOAD_EXECUTABLE" in rule_ids and ml_score >= 40:
        composite_score = max(int(round(raw_composite)), 78)
    elif "WEB_RULE_DOWNLOAD_APK" in rule_ids and apk_bonus >= 20:
        composite_score = max(int(round(raw_composite)), 75)
    elif "WEB_RULE_DOMAIN_HOPPING" in rule_ids and "WEB_RULE_CREDENTIAL_HARVESTING_FORM" in rule_ids:
        composite_score = max(int(round(raw_composite)), 75)
    elif "WEB_RULE_REDIRECT_LOOP" in rule_ids:
        composite_score = max(int(round(raw_composite)), 65)
    elif "WEB_RULE_UNENCRYPTED_CREDENTIAL_FORM" in rule_ids:
        composite_score = max(int(round(raw_composite)), 60)
    elif lex_score == 0 and web_rule_score == 0 and ml_score <= 10 and not threat_intelligence:
        composite_score = min(int(round(raw_composite)), 5)
    else:
        composite_score = min(max(int(round(raw_composite)), 0), 100)

    # Threat Intelligence Signals
    has_mal, is_corr, is_conflict, mal_cnt, intel_conf, _ = _process_threat_intelligence_signals(threat_intelligence)
    if has_mal:
        if is_corr:
            composite_score = max(composite_score, 88)
        elif is_conflict:
            composite_score = max(composite_score, 68)
        else:
            composite_score = max(composite_score, 75)

    composite_score = min(max(composite_score, 0), 100)

    # Risk level calibration
    if composite_score >= 80:
        level = "critical"
    elif composite_score >= 60:
        level = "high"
    elif composite_score >= 40:
        level = "medium"
    elif composite_score >= 20:
        level = "low"
    else:
        level = "very_low"

    # Analytical Confidence
    total_findings = len(url_findings) + len(web_findings)
    if has_mal and is_corr:
        confidence = 0.98
    elif has_mal and is_conflict:
        confidence = 0.72
    elif "WEB_RULE_SSRF_BLOCKED" in rule_ids:
        confidence = 0.98
    elif total_findings >= 3:
        confidence = 0.92
    elif total_findings >= 1:
        confidence = 0.85
    else:
        confidence = 0.88 if composite_score <= 10 else 0.75

    return composite_score, level, round(confidence, 2), lex_score, web_rule_score, ml_score






