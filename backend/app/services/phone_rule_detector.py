"""
ScamBuster — Phone Rule Detector (Phase 06)

Deterministic heuristic detection for phone numbers:
- Telecom structural analysis (validity, possibility, length)
- Number type risk profiling (e.g. premium-rate Wangiri fraud indicators)
- Weak digit pattern anomalies (excessive repetition, long sequential runs)
- Caller context impersonation checks (e.g. claiming to be bank/police from personal line)
- Threat intelligence reputation correlation

CRITICAL SAFETY CONSTRAINTS:
- Weak static patterns never dominate risk score.
- VoIP or mobile lines are NEVER flagged as malicious by themselves.
- Country codes are contextual indicators only.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.features.phone_features import extract_phone_features
from app.intelligence.base import PhoneIntelligenceResult
from app.schemas.scan import ThreatIndicator
from app.services.phone_normalizer import NormalizedPhone, normalize_phone_number


class PhoneRuleDetector:
    """
    Evaluates rule-based threat indicators for normalized phone numbers.
    """

    def analyze(
        self,
        phone: NormalizedPhone,
        intel_result: Optional[PhoneIntelligenceResult] = None,
        context: Optional[str] = None,
        default_region: Optional[str] = "IN",
    ) -> Tuple[int, List[ThreatIndicator]]:
        """
        Analyze a normalized phone number and return:
        - heuristic_risk_score (0-100 capped)
        - list of ThreatIndicator instances
        """
        indicators: List[ThreatIndicator] = []
        raw_score = 0

        # Extract static features
        features = extract_phone_features(phone, default_region=default_region)

        # 1. Structural Validity
        if not phone.is_possible or not phone.is_valid:
            raw_score += 25
            indicators.append(
                ThreatIndicator(
                    name="Invalid or Impossible Phone Number",
                    severity="medium",
                    description="Number failed international E.164 parsing or contains an impossible digit sequence.",
                    evidence=f"Valid: {phone.is_valid}, Possible: {phone.is_possible}",
                    rule_id="PHONE_RULE_INVALID_STRUCTURE",
                )
            )

        # 2. Premium-Rate or Wangiri High-Tariff Jurisdictions
        wangiri_prefixes = ("+232", "+247", "+252", "+881", "+882")
        if features["is_premium_rate"] == 1:
            raw_score += 35
            indicators.append(
                ThreatIndicator(
                    name="Premium-Rate Number Pattern",
                    severity="high",
                    description="Identified as a premium-rate telephony prefix. Callbacks to premium numbers incur excessive billing charges (Wangiri scam indicator).",
                    evidence=f"Number type: {phone.number_type_name}",
                    rule_id="PHONE_RULE_PREMIUM_RATE",
                )
            )
        elif any(phone.e164.startswith(pfx) for pfx in wangiri_prefixes):
            raw_score += 35
            indicators.append(
                ThreatIndicator(
                    name="Wangiri High-Tariff Callback Prefix",
                    severity="high",
                    description="Number originates from an international premium tariff jurisdiction frequently associated with one-ring missed call fraud (Wangiri).",
                    evidence=f"E.164 Prefix: {phone.e164[:4]}, Region: {phone.region_code}",
                    rule_id="PHONE_RULE_WANGIRI_PREFIX",
                )
            )

        # 3. High Digit Repetition / Spoofed Pattern (Weak Contextual Signal)
        if features["repeated_digit_ratio"] >= 0.7 or features["max_consecutive_repeated_digits"] >= 6:
            raw_score += 12
            indicators.append(
                ThreatIndicator(
                    name="High Digit Repetition",
                    severity="low",
                    description="Number contains unusually repetitive digit sequences commonly found in virtual spoofing or test numbers.",
                    evidence=f"Max consecutive: {features['max_consecutive_repeated_digits']}, Repetition ratio: {features['repeated_digit_ratio']}",
                    rule_id="PHONE_RULE_REPEATED_DIGITS",
                )
            )

        # 4. Long Sequential Digit Run (e.g., 1234567890)
        if features["sequential_digit_score"] >= 7:
            raw_score += 10
            indicators.append(
                ThreatIndicator(
                    name="Sequential Digit Sequence",
                    severity="low",
                    description="Number follows a continuous ascending or descending sequence, characteristic of placeholder or spoofed caller IDs.",
                    evidence=f"Longest sequential run: {features['sequential_digit_score']} digits",
                    rule_id="PHONE_RULE_SEQUENTIAL_DIGITS",
                )
            )

        # 5. Expected Region Mismatch (Contextual Info)
        if default_region and features["country_match"] == 0 and phone.country_code != 0:
            raw_score += 8
            indicators.append(
                ThreatIndicator(
                    name="Regional Origin Variance",
                    severity="info",
                    description="Number origin differs from the user's expected geographic region.",
                    evidence=f"Expected: {default_region.upper()}, Detected: {phone.region_code} (+{phone.country_code})",
                    rule_id="PHONE_RULE_REGION_MISMATCH",
                )
            )

        # 6. Caller Context Impersonation Check
        if context:
            ctx_lower = context.lower()
            authoritative_keywords = ["bank", "cbi", "police", "customs", "tax", "income tax", "irs", "arrest", "warrant", "fedex", "dhl", "rbi", "court", "lottery"]
            matched_keywords = [kw for kw in authoritative_keywords if kw in ctx_lower]
            if matched_keywords:
                # If caller claims to be official agency but is a standard personal mobile/unknown line
                if phone.number_type_name in ("MOBILE", "UNKNOWN") or any(phone.e164.startswith(pfx) for pfx in wangiri_prefixes):
                    raw_score += 25
                    indicators.append(
                        ThreatIndicator(
                            name="Official Organization Impersonation Risk",
                            severity="medium",
                            description="User context indicates caller claimed official institutional authority (bank, police, tax, courier) from an ordinary mobile or unverified personal line.",
                            evidence=f"Claimed context: '{context.strip()}' (matched: {', '.join(matched_keywords)})",
                            rule_id="PHONE_RULE_CONTEXT_IMPERSONATION",
                        )
                    )

        # 7. Threat Intelligence Reputation Correlation
        if intel_result and intel_result.status == "available":
            if intel_result.reputation == "reported_scam":
                raw_score += 55
                indicators.append(
                    ThreatIndicator(
                        name="Active Scam Intelligence Report",
                        severity="critical",
                        description="External threat intelligence reports confirm this number is associated with active fraudulent or abusive campaigns.",
                        evidence=f"Provider: {intel_result.provider}, Reports: {intel_result.report_count or 'Recorded'}",
                        rule_id="PHONE_RULE_INTEL_REPORTED_SCAM",
                    )
                )
            elif intel_result.reputation == "suspicious":
                raw_score += 30
                indicators.append(
                    ThreatIndicator(
                        name="Suspicious Caller Intelligence",
                        severity="medium",
                        description="External threat intelligence categorizes this number as exhibiting high-risk or suspicious telemetry.",
                        evidence=f"Provider: {intel_result.provider}",
                        rule_id="PHONE_RULE_INTEL_SUSPICIOUS",
                    )
                )

        capped_score = min(max(raw_score, 0), 100)
        return capped_score, indicators


# Singleton instance
phone_rule_detector = PhoneRuleDetector()
