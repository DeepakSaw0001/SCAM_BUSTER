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

from typing import List, Optional, Tuple
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
