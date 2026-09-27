"""
ScamBuster — Privacy Risk Rules, Combinations & Contextual Mismatch (Phase 08)

Analyzes:
1. Multi-permission privacy/security risk combinations.
2. Contextual alignment against declared/apparent application purpose.
3. Background execution and persistence capabilities.

CRITICAL PRINCIPLES:
- Sensitive permission != Privacy violation.
- Context mismatch != Malware (merely warrants additional user scrutiny).
- If application category is unknown, no artificial mismatch penalty is imposed.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# App Category Canonical Taxonomy
CAT_CALCULATOR = "calculator"
CAT_CAMERA = "camera"
CAT_MESSAGING = "messaging"
CAT_COMMUNICATION = "communication"
CAT_SOCIAL = "social"
CAT_BANKING = "banking"
CAT_FINANCE = "finance"
CAT_PRODUCTIVITY = "productivity"
CAT_GAME = "game"
CAT_EDUCATION = "education"
CAT_UTILITY = "utility"
CAT_TOOLS = "tools"
CAT_HEALTH = "health"
CAT_SHOPPING = "shopping"
CAT_UNKNOWN = "unknown"

# Expected Capability Mappings by Application Category
CATEGORY_EXPECTED_CAPABILITIES: Dict[str, Set[str]] = {
    CAT_CALCULATOR: set(),  # Calculators generally need no runtime permissions
    CAT_TOOLS: {"android.permission.VIBRATE"},
    CAT_UTILITY: {"android.permission.VIBRATE", "android.permission.INTERNET"},
    CAT_CAMERA: {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.READ_EXTERNAL_STORAGE",
        "android.permission.WRITE_EXTERNAL_STORAGE",
    },
    CAT_MESSAGING: {
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
        "android.permission.READ_CONTACTS",
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.INTERNET",
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_COMMUNICATION: {
        "android.permission.READ_PHONE_STATE",
        "android.permission.CALL_PHONE",
        "android.permission.READ_CONTACTS",
        "android.permission.RECORD_AUDIO",
        "android.permission.CAMERA",
        "android.permission.INTERNET",
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_SOCIAL: {
        "android.permission.CAMERA",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.ACCESS_COARSE_LOCATION",
        "android.permission.READ_MEDIA_IMAGES",
        "android.permission.READ_MEDIA_VIDEO",
        "android.permission.INTERNET",
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_BANKING: {
        "android.permission.INTERNET",
        "android.permission.USE_BIOMETRIC",
        "android.permission.USE_FINGERPRINT",
        "android.permission.CAMERA",  # QR code scanner / check deposit
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_FINANCE: {
        "android.permission.INTERNET",
        "android.permission.USE_BIOMETRIC",
        "android.permission.CAMERA",
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_GAME: {
        "android.permission.INTERNET",
        "android.permission.ACCESS_NETWORK_STATE",
        "android.permission.VIBRATE",
        "android.permission.WAKE_LOCK",
        "android.permission.POST_NOTIFICATIONS",
    },
    CAT_HEALTH: {
        "android.permission.BODY_SENSORS",
        "android.permission.ACTIVITY_RECOGNITION",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.INTERNET",
        "android.permission.POST_NOTIFICATIONS",
    },
}


@dataclass
class CombinationFinding:
    name: str
    severity: str                       # "critical", "high", "medium", "low"
    matched_permissions: List[str]
    description: str
    privacy_concern: str
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity,
            "matched_permissions": self.matched_permissions,
            "description": self.description,
            "privacy_concern": self.privacy_concern,
            "confidence": self.confidence,
        }


@dataclass
class ContextAnalysisResult:
    declared_category: str
    context_status: str                 # "established", "inferred", "unknown"
    mismatch_level: str                 # "LOW", "MEDIUM", "HIGH", "NONE"
    mismatch_score: int                 # 0 to 100
    unexpected_permissions: List[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "declared_category": self.declared_category,
            "context_status": self.context_status,
            "mismatch_level": self.mismatch_level,
            "mismatch_score": self.mismatch_score,
            "unexpected_permissions": self.unexpected_permissions,
            "explanation": self.explanation,
        }


def evaluate_permission_combinations(permissions: List[str]) -> List[CombinationFinding]:
    """
    Evaluate requested permissions for co-occurring capability combinations
    that represent elevated privacy or security attack surfaces.
    """
    findings: List[CombinationFinding] = []
    p_set = set(p.strip() for p in permissions)

    has_sms = bool(p_set.intersection({"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS"}))
    has_contacts = "android.permission.READ_CONTACTS" in p_set
    has_phone = bool(p_set.intersection({"android.permission.READ_PHONE_STATE", "android.permission.CALL_PHONE", "android.permission.READ_CALL_LOG"}))

    has_location = bool(p_set.intersection({"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION"}))
    has_mic = "android.permission.RECORD_AUDIO" in p_set
    has_camera = "android.permission.CAMERA" in p_set

    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in p_set
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in p_set
    has_network = "android.permission.INTERNET" in p_set
    has_boot = "android.permission.RECEIVE_BOOT_COMPLETED" in p_set
    has_install = "android.permission.REQUEST_INSTALL_PACKAGES" in p_set

    # 1. Broad Communication & Interception Cluster (SMS + Contacts + Phone)
    if has_sms and has_contacts and has_phone:
        findings.append(
            CombinationFinding(
                name="Comprehensive Communication Access",
                severity="high",
                matched_permissions=["SMS", "READ_CONTACTS", "Phone/Call State"],
                description="Simultaneously requests address book, phone state/call logs, and SMS messaging.",
                privacy_concern="Allows deep inspection of personal communications, contact graphs, and message contents.",
            )
        )

    # 2. Ambient Surveillance & Physical Sensor Cluster (Location + Mic + Camera)
    if has_location and has_mic and has_camera:
        findings.append(
            CombinationFinding(
                name="Broad Physical Sensor Access",
                severity="high",
                matched_permissions=["Location", "RECORD_AUDIO", "CAMERA"],
                description="Application can access physical surroundings via camera, audio recording, and geographic tracking.",
                privacy_concern="Creates significant audio/visual and movement surveillance capability.",
            )
        )

    # 3. Elevated Interface Hijacking Cluster (Accessibility + Overlay)
    if has_accessibility and has_overlay:
        findings.append(
            CombinationFinding(
                name="Full UI Observation and Overlay Capability",
                severity="critical",
                matched_permissions=["BIND_ACCESSIBILITY_SERVICE", "SYSTEM_ALERT_WINDOW"],
                description="Combines drawing on top of active screens with accessibility-based UI inspection and automated input.",
                privacy_concern="Permits observing on-screen PINs/passwords and overlaying deceptive prompt interfaces.",
            )
        )

    # 4. Background Persistence with Sensitive Dispatch (Boot + SMS / Location)
    if has_boot and (has_sms or has_location):
        sens = "SMS transmission" if has_sms else "continuous location tracking"
        findings.append(
            CombinationFinding(
                name="Autostart Sensitive Capability",
                severity="medium",
                matched_permissions=["RECEIVE_BOOT_COMPLETED", "SMS" if has_sms else "Location"],
                description=f"Combines automatic startup on device reboot with {sens}.",
                privacy_concern="Enables background operation without requiring the user to explicitly open the application.",
            )
        )

    # 5. Secondary Package Dropper (Install Packages + Network)
    if has_install and has_network:
        findings.append(
            CombinationFinding(
                name="Unverified Application Downloader & Installer",
                severity="high",
                matched_permissions=["REQUEST_INSTALL_PACKAGES", "INTERNET"],
                description="Requests capability to download and prompt installation of secondary Android packages.",
                privacy_concern="Can bypass centralized app-store verification by dropping supplementary software.",
            )
        )

    return findings


def evaluate_context_mismatch(
    category: Optional[str],
    permissions: List[str],
    package_name: str = "",
    app_label: str = "",
) -> ContextAnalysisResult:
    """
    Examine requested permissions against the apparent application purpose.
    If category is unknown, gracefully reports unknown context without penalties.
    """
    cat_clean = (category or "").strip().lower()
    p_set = set(p.strip() for p in permissions)

    if not cat_clean or cat_clean in ("unknown", "none", "other") or cat_clean not in CATEGORY_EXPECTED_CAPABILITIES:
        # Attempt soft inference from package name or label if obvious
        combined_text = f"{package_name.lower()} {app_label.lower()}"
        if "calculator" in combined_text:
            cat_clean = CAT_CALCULATOR
            context_status = "inferred"
        elif "camera" in combined_text or "photo" in combined_text:
            cat_clean = CAT_CAMERA
            context_status = "inferred"
        elif "torch" in combined_text or "flashlight" in combined_text:
            cat_clean = CAT_TOOLS
            context_status = "inferred"
        else:
            return ContextAnalysisResult(
                declared_category="unknown",
                context_status="unknown",
                mismatch_level="NONE",
                mismatch_score=0,
                unexpected_permissions=[],
                explanation="Application context could not be established. No mismatch penalty applied.",
            )
    else:
        context_status = "established"

    expected_set = CATEGORY_EXPECTED_CAPABILITIES.get(cat_clean, set())

    # High-sensitivity permissions that are especially anomalous when out-of-context
    HIGH_ANOMALY_PERMS = {
        "android.permission.READ_SMS": 30,
        "android.permission.RECEIVE_SMS": 30,
        "android.permission.SEND_SMS": 30,
        "android.permission.BIND_ACCESSIBILITY_SERVICE": 40,
        "android.permission.SYSTEM_ALERT_WINDOW": 25,
        "android.permission.BIND_DEVICE_ADMIN": 35,
        "android.permission.RECORD_AUDIO": 20,
        "android.permission.CAMERA": 20,
        "android.permission.READ_CONTACTS": 20,
        "android.permission.ACCESS_FINE_LOCATION": 20,
        "android.permission.ACCESS_BACKGROUND_LOCATION": 30,
    }

    unexpected: List[str] = []
    penalty = 0

    for p in p_set:
        if p not in expected_set and p in HIGH_ANOMALY_PERMS:
            unexpected.append(p)
            penalty += HIGH_ANOMALY_PERMS[p]

    mismatch_score = min(penalty, 100)

    if mismatch_score >= 60:
        level = "HIGH"
        expl = (
            f"Application identified as '{cat_clean}' requests highly unexpected and sensitive permissions "
            f"({', '.join([u.split('.')[-1] for u in unexpected[:4]])}) that exceed standard functional requirements."
        )
    elif mismatch_score >= 25:
        level = "MEDIUM"
        expl = (
            f"Application identified as '{cat_clean}' requests some sensitive capabilities "
            f"({', '.join([u.split('.')[-1] for u in unexpected[:3]])}) that may not be strictly necessary for its stated core utility."
        )
    else:
        level = "LOW"
        expl = f"Permissions align reasonably with expected functionality for a '{cat_clean}' application."

    return ContextAnalysisResult(
        declared_category=cat_clean,
        context_status=context_status,
        mismatch_level=level,
        mismatch_score=mismatch_score,
        unexpected_permissions=unexpected,
        explanation=expl,
    )
