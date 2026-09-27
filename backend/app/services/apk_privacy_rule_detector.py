"""
ScamBuster — Android APK Privacy & Permission Risk Rule Detector (Phase 08)

Audits requested Android permissions, capability combinations, static bytecode API correlations,
and contextual necessity to determine overall privacy risk exposure.

CRITICAL PRINCIPLES:
- Privacy Score represents "degree of privacy/security attention warranted by observed capabilities".
- Privacy Score is NOT malware probability (a legitimate social app can have High Privacy Risk).
- Never claims runtime execution or data theft without dynamic evidence.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from app.security.android_permissions import (
    AndroidPermissionMetadata,
    CombinationFinding,
    ContextAnalysisResult,
    PermissionApiCorrelation,
    correlate_permissions_with_apis,
    evaluate_context_mismatch,
    evaluate_permission_combinations,
    get_permission_metadata,
    is_high_impact_permission,
    SENSITIVITY_HIGH,
    SENSITIVITY_VERY_HIGH,
)


@dataclass
class PrivacyIndicator:
    name: str
    severity: str                       # "critical", "high", "medium", "low", "info"
    description: str
    evidence: str
    source: str                         # "MANIFEST", "STATIC_CODE", "COMPONENT", "RULE"
    confidence: str = "HIGH"            # "HIGH", "MEDIUM", "LOW"
    rule_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "description": self.description,
            "evidence": self.evidence,
            "source": self.source,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
        }


@dataclass
class ApkPrivacyAnalysisResult:
    privacy_score: int                  # 0 to 100
    privacy_risk_level: str             # "critical", "high", "medium", "low", "very_low"
    total_requested_count: int
    sensitive_permissions_count: int
    high_impact_count: int
    categories_requested: List[str]
    permissions_detail: List[Dict[str, Any]]
    high_impact_capabilities: List[str]
    combination_findings: List[Dict[str, Any]]
    context_analysis: Dict[str, Any]
    api_correlations: List[Dict[str, Any]]
    indicators: List[PrivacyIndicator]
    background_capabilities: List[str]
    storage_model: Dict[str, str]
    summary: str
    recommendation: str
    limitation_disclaimer: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "privacy_score": self.privacy_score,
            "privacy_risk_level": self.privacy_risk_level,
            "total_requested_count": self.total_requested_count,
            "sensitive_permissions_count": self.sensitive_permissions_count,
            "high_impact_count": self.high_impact_count,
            "categories_requested": self.categories_requested,
            "permissions_detail": self.permissions_detail,
            "high_impact_capabilities": self.high_impact_capabilities,
            "combination_findings": self.combination_findings,
            "context_analysis": self.context_analysis,
            "api_correlations": self.api_correlations,
            "indicators": [ind.to_dict() for ind in self.indicators],
            "background_capabilities": self.background_capabilities,
            "storage_model": self.storage_model,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "limitation_disclaimer": self.limitation_disclaimer,
        }


class ApkPrivacyRuleDetector:
    """Evaluates privacy and permission metrics on Android application packages."""

    def analyze(
        self,
        declared_permissions: List[str],
        category: Optional[str] = None,
        package_name: str = "",
        app_label: str = "",
        target_sdk: Optional[int] = None,
        dex_indicators: Optional[Dict[str, List[str]]] = None,
        dex_data: Optional[bytes] = None,
        service_count: int = 0,
        receiver_count: int = 0,
        exported_component_count: int = 0,
    ) -> ApkPrivacyAnalysisResult:
        indicators: List[PrivacyIndicator] = []
        raw_score = 0

        # 1. Permission Catalog Resolution & Categorization
        meta_list: List[AndroidPermissionMetadata] = []
        categories_set: Set[str] = set()
        sensitive_count = 0
        high_impact_names: List[str] = []
        p_set = set(p.strip() for p in declared_permissions)

        for p in p_set:
            meta = get_permission_metadata(p, target_sdk=target_sdk)
            meta_list.append(meta)
            categories_set.add(meta.category)

            if meta.sensitivity in (SENSITIVITY_HIGH, SENSITIVITY_VERY_HIGH):
                sensitive_count += 1

            if is_high_impact_permission(p):
                high_impact_names.append(meta.short_name)

        high_impact_names = sorted(list(set(high_impact_names)))

        # 2. Permission API Correlation (Static Bytecode Mapping)
        correlations, correlated_count = correlate_permissions_with_apis(
            requested_permissions=list(p_set),
            dex_data=dex_data,
            dex_indicators=dex_indicators,
        )

        for corr in correlations:
            if corr.status == "CORRELATED":
                indicators.append(
                    PrivacyIndicator(
                        name=f"Correlated API Reference: {corr.permission.split('.')[-1]}",
                        severity="medium",
                        description=f"Permission declaration matches static bytecode API references ({', '.join(corr.matched_apis[:2])}).",
                        evidence=f"API: {', '.join(corr.matched_apis)}",
                        source="STATIC_CODE",
                        confidence="HIGH",
                        rule_id="PRIVACY_RULE_API_CORRELATED",
                    )
                )

        # 3. High-Impact Capabilities Evaluation
        if "BIND_ACCESSIBILITY_SERVICE" in p_set:
            raw_score += 35
            indicators.append(
                PrivacyIndicator(
                    name="Accessibility Service Capability",
                    severity="critical",
                    description="Application declares capability to bind to an Accessibility Service, allowing on-screen UI inspection and touch dispatch.",
                    evidence="android.permission.BIND_ACCESSIBILITY_SERVICE",
                    source="MANIFEST",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_ACCESSIBILITY",
                )
            )

        if "SYSTEM_ALERT_WINDOW" in p_set:
            raw_score += 25
            indicators.append(
                PrivacyIndicator(
                    name="System Alert Window Overlay",
                    severity="high",
                    description="Application can draw overlay windows over other running applications.",
                    evidence="android.permission.SYSTEM_ALERT_WINDOW",
                    source="MANIFEST",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_OVERLAY",
                )
            )

        if "BIND_DEVICE_ADMIN" in p_set:
            raw_score += 30
            indicators.append(
                PrivacyIndicator(
                    name="Device Administration Privilege",
                    severity="high",
                    description="Application requests Device Administrator privileges, which can govern lockscreen security and device policies.",
                    evidence="android.permission.BIND_DEVICE_ADMIN",
                    source="MANIFEST",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_DEVICE_ADMIN",
                )
            )

        if "REQUEST_INSTALL_PACKAGES" in p_set:
            raw_score += 20
            indicators.append(
                PrivacyIndicator(
                    name="Secondary Package Installation",
                    severity="medium",
                    description="Application can request installation of additional Android packages outside the Play Store.",
                    evidence="android.permission.REQUEST_INSTALL_PACKAGES",
                    source="MANIFEST",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_PACKAGE_INSTALLER",
                )
            )

        # 4. Multi-Permission Combination Analysis
        comb_findings = evaluate_permission_combinations(list(p_set))
        for comb in comb_findings:
            if comb.severity == "critical":
                raw_score += 30
            elif comb.severity == "high":
                raw_score += 20
            elif comb.severity == "medium":
                raw_score += 15
            else:
                raw_score += 10

            indicators.append(
                PrivacyIndicator(
                    name=comb.name,
                    severity=comb.severity,
                    description=f"{comb.description} {comb.privacy_concern}",
                    evidence=f"Permissions: {', '.join(comb.matched_permissions)}",
                    source="RULE",
                    confidence=comb.confidence,
                    rule_id="PRIVACY_RULE_COMBINATION",
                )
            )

        # 5. Application Context Mismatch Analysis
        context_res = evaluate_context_mismatch(
            category=category,
            permissions=list(p_set),
            package_name=package_name,
            app_label=app_label,
        )

        if context_res.context_status != "unknown" and context_res.mismatch_score > 0:
            raw_score += int(round(context_res.mismatch_score * 0.35))
            indicators.append(
                PrivacyIndicator(
                    name=f"Context Mismatch ({context_res.mismatch_level})",
                    severity="high" if context_res.mismatch_level == "HIGH" else "medium",
                    description=context_res.explanation,
                    evidence=f"Declared category: {context_res.declared_category}, Unexpected: {', '.join([u.split('.')[-1] for u in context_res.unexpected_permissions])}",
                    source="RULE",
                    confidence="MEDIUM",
                    rule_id="PRIVACY_RULE_CONTEXT_MISMATCH",
                )
            )

        # 6. Background Capability and Persistence
        background_caps: List[str] = []
        if "android.permission.RECEIVE_BOOT_COMPLETED" in p_set:
            background_caps.append("Automatic boot autostart")
            raw_score += 10
            indicators.append(
                PrivacyIndicator(
                    name="Boot Autostart Capability",
                    severity="low",
                    description="Application can launch services automatically upon system startup.",
                    evidence="android.permission.RECEIVE_BOOT_COMPLETED",
                    source="MANIFEST",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_BOOT_AUTOSTART",
                )
            )

        if service_count > 0:
            background_caps.append(f"{service_count} background service(s)")
        if receiver_count > 0:
            background_caps.append(f"{receiver_count} broadcast receiver(s)")

        if exported_component_count >= 5:
            raw_score += 10
            indicators.append(
                PrivacyIndicator(
                    name="Broad Exported Component Surface",
                    severity="low",
                    description=f"APK exposes {exported_component_count} exported components accessible to other apps on the device.",
                    evidence=f"Exported count: {exported_component_count}",
                    source="COMPONENT",
                    confidence="HIGH",
                    rule_id="PRIVACY_RULE_EXPORTED_COMPONENTS",
                )
            )

        # Marginal scaling for sensitive count
        raw_score += min(sensitive_count * 4, 25)

        # Clamp privacy score 0 to 100
        privacy_score = min(max(raw_score, 0), 100)

        # Calibrate Privacy Risk Level
        if privacy_score >= 75:
            privacy_risk_level = "critical"
        elif privacy_score >= 50:
            privacy_risk_level = "high"
        elif privacy_score >= 30:
            privacy_risk_level = "medium"
        elif privacy_score >= 15:
            privacy_risk_level = "low"
        else:
            privacy_risk_level = "very_low"

        # Storage model explanation based on target SDK
        from app.security.android_permissions.version import get_storage_permission_model
        storage_model = get_storage_permission_model(target_sdk)

        # User-facing summary
        summary = self._generate_summary(
            privacy_score=privacy_score,
            privacy_risk_level=privacy_risk_level,
            total_count=len(p_set),
            sensitive_count=sensitive_count,
            high_impact_names=high_impact_names,
            context_res=context_res,
        )

        # User-facing recommendation
        recommendation = self._generate_recommendation(
            privacy_risk_level=privacy_risk_level,
            high_impact_names=high_impact_names,
            context_res=context_res,
        )

        disclaimer = (
            "IMPORTANT LIMITATION: This analysis is based strictly on static APK manifest inspection, "
            "capability mapping, and bytecode references. It demonstrates what permissions are requested "
            "and what APIs are present; it does NOT confirm whether the user granted these permissions "
            "or prove that data was accessed or exfiltrated at runtime."
        )

        return ApkPrivacyAnalysisResult(
            privacy_score=privacy_score,
            privacy_risk_level=privacy_risk_level,
            total_requested_count=len(p_set),
            sensitive_permissions_count=sensitive_count,
            high_impact_count=len(high_impact_names),
            categories_requested=sorted(list(categories_set)),
            permissions_detail=[m.to_dict() for m in meta_list],
            high_impact_capabilities=high_impact_names,
            combination_findings=[f.to_dict() for f in comb_findings],
            context_analysis=context_res.to_dict(),
            api_correlations=[c.to_dict() for c in correlations],
            indicators=indicators,
            background_capabilities=background_caps,
            storage_model=storage_model,
            summary=summary,
            recommendation=recommendation,
            limitation_disclaimer=disclaimer,
        )

    def _generate_summary(
        self,
        privacy_score: int,
        privacy_risk_level: str,
        total_count: int,
        sensitive_count: int,
        high_impact_names: List[str],
        context_res: ContextAnalysisResult,
    ) -> str:
        if privacy_risk_level in ("critical", "high"):
            high_str = f", including high-impact capabilities ({', '.join(high_impact_names[:3])})" if high_impact_names else ""
            mismatch_str = f" Contextual analysis flagged inconsistent capability requests for category '{context_res.declared_category}'." if context_res.mismatch_level in ("HIGH", "MEDIUM") else ""
            return (
                f"Elevated privacy exposure ({privacy_risk_level.upper()} privacy risk, score {privacy_score}/100). "
                f"Application requests {total_count} total permissions ({sensitive_count} sensitive){high_str}.{mismatch_str}"
            )
        if privacy_risk_level == "medium":
            return (
                f"Moderate privacy footprint ({privacy_score}/100). The application requests {sensitive_count} sensitive "
                f"permissions out of {total_count} total declarations. Capabilities warrant review against stated functionality."
            )
        return (
            f"Low privacy footprint ({privacy_score}/100). Requested permissions conform to standard "
            f"development patterns with minimal sensitive capability exposure."
        )

    def _generate_recommendation(
        self,
        privacy_risk_level: str,
        high_impact_names: List[str],
        context_res: ContextAnalysisResult,
    ) -> str:
        if privacy_risk_level in ("critical", "high"):
            advice = []
            if "BIND_ACCESSIBILITY_SERVICE" in high_impact_names:
                advice.append("Do NOT grant Accessibility Service permissions unless you strictly trust the publisher.")
            if "SYSTEM_ALERT_WINDOW" in high_impact_names:
                advice.append("Avoid granting 'Display over other apps' privileges to prevent deceptive overlays.")
            if "READ_SMS" in high_impact_names or "RECEIVE_SMS" in high_impact_names:
                advice.append("Review why this application requires access to private SMS and 2FA tokens.")
            if context_res.mismatch_level == "HIGH":
                advice.append(f"Consider whether a '{context_res.declared_category}' application legitimately requires these capabilities.")
            if not advice:
                advice.append("Audit requested runtime permissions in Android Settings and grant only strictly essential access.")
            return " ".join(advice)
        if privacy_risk_level == "medium":
            return "Exercise standard caution. Review permission prompts when first launching the app and deny access to unneeded sensors."
        return "Standard application hygiene applies: keep applications updated and obtain them from verified sources."


apk_privacy_rule_detector = ApkPrivacyRuleDetector()


def analyze_apk_privacy(
    declared_permissions: List[str],
    category: Optional[str] = None,
    package_name: str = "",
    app_label: str = "",
    target_sdk: Optional[int] = None,
    dex_indicators: Optional[Dict[str, List[str]]] = None,
    dex_data: Optional[bytes] = None,
    service_count: int = 0,
    receiver_count: int = 0,
    exported_component_count: int = 0,
) -> ApkPrivacyAnalysisResult:
    """Convenience functional wrapper for apk_privacy_rule_detector.analyze."""
    return apk_privacy_rule_detector.analyze(
        declared_permissions=declared_permissions,
        category=category,
        package_name=package_name,
        app_label=app_label,
        target_sdk=target_sdk,
        dex_indicators=dex_indicators,
        dex_data=dex_data,
        service_count=service_count,
        receiver_count=receiver_count,
        exported_component_count=exported_component_count,
    )
