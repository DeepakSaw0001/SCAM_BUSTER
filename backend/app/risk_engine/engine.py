"""
ScamBuster Risk Fusion Engine

Correlates and fuses:
1. Cybersecurity Heuristic Detection Engines (rule scores & technical indicators)
2. Machine Learning Classifiers (probabilistic statistical signals)

Produces an explainable, unified composite risk score, risk level, threat indicators,
and contextual actionable security recommendations.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from app.schemas.scan import MLMetadata, ScanResultResponse, ThreatIndicator


def fuse_risk_analysis(
    scan_type: str,
    target: str,
    heuristic_result: Dict[str, Any],
    ml_result: Optional[Dict[str, Any]] = None,
) -> ScanResultResponse:
    """
    Fuse heuristic cyber analysis and ML probabilistic inference into a single
    coherent, explainable risk assessment.
    """
    heuristic_score = int(heuristic_result.get("score", 0))
    raw_indicators = heuristic_result.get("indicators", [])

    has_critical = any(ind.get("severity") == "CRITICAL" for ind in raw_indicators)
    has_high = any(ind.get("severity") == "HIGH" for ind in raw_indicators)

    ml_meta: Optional[MLMetadata] = None
    composite_score = heuristic_score

    # ── 1. Weight & Combine with ML Signal ───────────────────────────────────
    if scan_type == "url":
        if ml_result and "malicious_probability" in ml_result:
            ml_prob = float(ml_result["malicious_probability"])
            ml_score = ml_prob * 100
            composite_score = round(0.55 * heuristic_score + 0.45 * ml_score)
            
            ml_meta = MLMetadata(
                model_name=ml_result.get("model", "Random Forest URL Classifier"),
                model_version=ml_result.get("model_version", "1.0.0"),
                prediction=ml_result.get("prediction"),
                probability=round(ml_result.get("probability", 0.0), 4),
                target_probability=round(ml_prob, 4),
                features_used=ml_result.get("features_used", 17),
                details={"extracted_features": ml_result.get("extracted_features")},
            )
            # Add ML signal as an indicator if probability is notable
            if ml_prob >= 0.70:
                raw_indicators.append({
                    "name": "Machine Learning Malicious Classification",
                    "severity": "HIGH",
                    "description": f"URL structural features evaluated by Random Forest classifier with {round(ml_prob * 100, 1)}% malicious probability.",
                    "evidence": f"Model: {ml_result.get('model')} (v{ml_result.get('model_version')})",
                })
        # Hard cybersecurity floor rule
        if has_critical:
            composite_score = max(composite_score, 75)
        elif has_high:
            composite_score = max(composite_score, 55)

    elif scan_type in ("text", "email"):
        if ml_result and "spam_probability" in ml_result:
            ml_prob = float(ml_result["spam_probability"])
            ml_score = ml_prob * 100
            
            weight_h = 0.50 if scan_type == "text" else 0.60
            weight_m = 1.0 - weight_h
            composite_score = round(weight_h * heuristic_score + weight_m * ml_score)

            ml_meta = MLMetadata(
                model_name=ml_result.get("model", "TF-IDF + Logistic Regression"),
                model_version=ml_result.get("model_version", "1.0.0"),
                prediction=ml_result.get("prediction"),
                probability=round(ml_result.get("probability", 0.0), 4),
                target_probability=round(ml_prob, 4),
                features_used=None,
                details={"preprocessed_input": ml_result.get("preprocessed_input")},
            )

            if ml_prob >= 0.70:
                raw_indicators.append({
                    "name": "Machine Learning Spam/Scam Classification",
                    "severity": "HIGH",
                    "description": f"NLP lexical feature vector classified with {round(ml_prob * 100, 1)}% spam/scam probability.",
                    "evidence": f"Model: {ml_result.get('model')} (v{ml_result.get('model_version')})",
                })
        # Hard cybersecurity floor rule
        if has_critical:
            composite_score = max(composite_score, 80)
        elif has_high:
            composite_score = max(composite_score, 60)

    elif scan_type in ("phone", "apk"):
        composite_score = heuristic_score
        if has_critical:
            composite_score = max(composite_score, 80)
        elif has_high:
            composite_score = max(composite_score, 60)

    # Bound composite score
    composite_score = min(max(composite_score, 0), 100)

    # ── 2. Determine Risk Level ──────────────────────────────────────────────
    if composite_score >= 70:
        risk_level = "DANGEROUS"
    elif composite_score >= 35:
        risk_level = "SUSPICIOUS"
    else:
        risk_level = "SAFE"

    # ── 3. Build Formatted Indicators ────────────────────────────────────────
    # Sort indicators: CRITICAL > HIGH > MEDIUM > LOW > INFO
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    formatted_indicators = [
        ThreatIndicator(
            name=ind["name"],
            severity=ind["severity"],
            description=ind["description"],
            evidence=ind.get("evidence"),
        )
        for ind in sorted(raw_indicators, key=lambda x: severity_order.get(x["severity"], 5))
    ]

    # ── 4. Generate Explainable Summary ──────────────────────────────────────
    if risk_level == "DANGEROUS":
        summary = (
            f"CRITICAL THREAT DETECTED ({composite_score}/100). "
            f"The target exhibits severe malicious indicators including {len(formatted_indicators)} security triggers. "
            f"Immediate caution is strongly advised."
        )
    elif risk_level == "SUSPICIOUS":
        summary = (
            f"ELEVATED RISK DETECTED ({composite_score}/100). "
            f"Multiple suspicious characteristics or deceptive patterns were identified. "
            f"Exercise caution and verify through out-of-band channels."
        )
    else:
        summary = (
            f"LOW RISK ASSESSMENT ({composite_score}/100). "
            f"No prominent malicious indicators or automated abuse patterns were detected."
        )

    # ── 5. Generate Contextual Recommendations ──────────────────────────────
    recommendations: List[str] = []
    if risk_level == "DANGEROUS":
        recommendations.append("Do NOT interact with, click, or enter any credentials into this target.")
        recommendations.append("Block the originating sender or domain immediately across your devices.")
        if scan_type == "apk":
            recommendations.append("Immediately uninstall the application and revoke device administrator/accessibility permissions.")
            recommendations.append("Conduct a full malware scan and change banking credentials from a separate secure device.")
        elif scan_type == "url":
            recommendations.append("Report the URL to anti-phishing authorities (Google Safe Browsing, PhishTank).")
        elif scan_type in ("text", "phone"):
            recommendations.append("Forward suspicious message to carrier fraud reporting (SMS to 7726).")
    elif risk_level == "SUSPICIOUS":
        recommendations.append("Do not download files or provide sensitive personal or financial information.")
        recommendations.append("Verify the claimed organization directly using officially listed public contacts.")
        if scan_type == "apk":
            recommendations.append("Review whether granted permissions (SMS, contacts, overlay) are truly necessary for app function.")
    else:
        recommendations.append("Standard security vigilance applies: ensure HTTPS is used and sender identity is legitimate.")

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    return ScanResultResponse(
        id=scan_id,
        scan_type=scan_type,
        target=target,
        timestamp=now,
        composite_risk_score=composite_score,
        risk_level=risk_level,
        summary=summary,
        heuristic_score=heuristic_score,
        indicators=formatted_indicators,
        recommendations=recommendations,
        ml_metadata=ml_meta,
        technical_details=heuristic_result.get("details"),
    )
