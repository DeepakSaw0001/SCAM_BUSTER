"""
ScamBuster — Android APK Static Rule Detector (Phase 07)

Evaluates heuristic cybersecurity rules on extracted APK properties:
- Dangerous permission clusters (Banking Trojans, Spyware, Droppers, SMS Spammers)
- Bytecode execution anomalies (Dynamic DEX loading, root/shell command execution)
- Component exposure risks (Exported services, receivers)
- Signing certificate integrity (Debug certificate abuse)
- Embedded URL threat correlations
- External threat intelligence reputation

CRITICAL PRINCIPLES:
- Rules produce concrete, explainable evidence.
- A single permission never triggers a false-positive malware declaration.
"""

from typing import Any, Dict, List, Optional, Tuple

from app.schemas.scan import ThreatIndicator
from app.services.apk_analyzer import ApkStaticAnalysisResult
from app.intelligence.apk_intelligence import ApkIntelligenceResult


class ApkRuleDetector:
    """Evaluates rule-based security indicators on static APK analysis results."""

    def analyze(
        self,
        analysis: ApkStaticAnalysisResult,
        intel_result: Optional[ApkIntelligenceResult] = None,
    ) -> Tuple[int, List[ThreatIndicator]]:
        indicators: List[ThreatIndicator] = []
        raw_score = 0

        # 1. Permission Cluster Indicators (From Manifest Analysis)
        for cluster in analysis.permission_report.clusters:
            if cluster.severity == "critical":
                raw_score += 45
            elif cluster.severity == "high":
                raw_score += 30
            elif cluster.severity == "medium":
                raw_score += 20
            else:
                raw_score += 10

            indicators.append(
                ThreatIndicator(
                    name=cluster.name,
                    severity=cluster.severity,
                    description=cluster.description,
                    evidence=f"Matched permissions: {', '.join(cluster.matched_permissions)}",
                    rule_id=cluster.rule_id,
                )
            )

        # 2. Excessive Sensitive Permissions Volume
        if analysis.permission_report.dangerous_count >= 8:
            raw_score += 20
            indicators.append(
                ThreatIndicator(
                    name="High Volume of Sensitive Permissions",
                    severity="medium",
                    description="Application requests an unusually large number of runtime dangerous permissions.",
                    evidence=f"{analysis.permission_report.dangerous_count} dangerous permissions declared",
                    rule_id="APK_RULE_EXCESSIVE_DANGEROUS_PERMS",
                )
            )

        # 3. Dynamic Code Loading References in DEX
        if analysis.dex_analysis.dynamic_code_loading_indicators:
            raw_score += 25
            indicators.append(
                ThreatIndicator(
                    name="Dynamic Code Loading APIs Present",
                    severity="medium",
                    description="Bytecode references dynamic class loading mechanisms (DexClassLoader/PathClassLoader) capable of executing unverified secondary payloads.",
                    evidence=f"Found: {', '.join(analysis.dex_analysis.dynamic_code_loading_indicators[:4])}",
                    rule_id="APK_RULE_DYNAMIC_CODE_LOADING",
                )
            )

        # 4. Command Execution & Shell Invocation
        if analysis.dex_analysis.command_execution_indicators:
            raw_score += 30
            indicators.append(
                ThreatIndicator(
                    name="Process Execution / Root Shell References",
                    severity="high",
                    description="Bytecode contains invocations of Runtime.exec or shell binaries (/system/bin/sh, su) frequently associated with privilege escalation or root detection bypass.",
                    evidence=f"Found: {', '.join(analysis.dex_analysis.command_execution_indicators[:3])}",
                    rule_id="APK_RULE_SHELL_EXECUTION",
                )
            )

        # 5. Exported Component Surface Exposure
        if analysis.exported_component_count >= 10:
            raw_score += 15
            indicators.append(
                ThreatIndicator(
                    name="Broad Exported Component Attack Surface",
                    severity="low",
                    description="Application declares multiple exported services or broadcast receivers accessible to any other application installed on the device.",
                    evidence=f"{analysis.exported_component_count} exported components identified",
                    rule_id="APK_RULE_EXPORTED_COMPONENTS",
                )
            )

        # 6. Embedded Malicious / Phishing URLs
        suspicious_urls = [u for u in analysis.embedded_urls if u.risk_score >= 60]
        if suspicious_urls:
            raw_score += 30
            indicators.append(
                ThreatIndicator(
                    name="High-Risk Embedded External URLs",
                    severity="high",
                    description="Static resources or bytecode contain hardcoded URLs flagged as high-risk or phishing destinations by ScamBuster URL security analysis.",
                    evidence=f"Identified {len(suspicious_urls)} high-risk link(s): e.g. {suspicious_urls[0].url[:40]}...",
                    rule_id="APK_RULE_SUSPICIOUS_EMBEDDED_URL",
                )
            )

        # 7. Debug Signing Certificate Anomaly
        if analysis.certificate.is_debug_certificate:
            raw_score += 20
            indicators.append(
                ThreatIndicator(
                    name="Debug Signing Certificate",
                    severity="medium",
                    description="APK is signed with an insecure Android Debug keystore certificate (common in test builds, unofficial repackaged apps, or rapid malware distribution).",
                    evidence=f"Subject: {analysis.certificate.subject}",
                    rule_id="APK_RULE_DEBUG_CERTIFICATE",
                )
            )

        # 8. Threat Intelligence Reputation Correlation
        if intel_result and intel_result.status == "available":
            if intel_result.reputation == "known_malware":
                raw_score += 60
                indicators.append(
                    ThreatIndicator(
                        name="Known Malware Hash Match",
                        severity="critical",
                        description=f"External threat intelligence identified APK hash as verified malware ({intel_result.malware_family or 'Abusive Android Trojan'}).",
                        evidence=f"Provider: {intel_result.provider} (Detections: {intel_result.detection_ratio or 'Confirmed'})",
                        rule_id="APK_RULE_INTEL_MALWARE_MATCH",
                    )
                )
            elif intel_result.reputation == "suspicious":
                raw_score += 30
                indicators.append(
                    ThreatIndicator(
                        name="Suspicious APK Threat Intelligence",
                        severity="medium",
                        description="External threat intelligence categorizes APK hash as having suspicious historical reputation.",
                        evidence=f"Provider: {intel_result.provider}",
                        rule_id="APK_RULE_INTEL_SUSPICIOUS",
                    )
                )

        capped_score = min(max(raw_score, 0), 100)
        return capped_score, indicators


apk_rule_detector = ApkRuleDetector()
