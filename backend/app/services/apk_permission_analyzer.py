"""
ScamBuster — Android APK Permission Taxonomy & Risk Analyzer (Phase 07)

Categorizes Android permissions using authoritative AOSP permission protection levels
(NORMAL, DANGEROUS, SIGNATURE, SPECIAL, SYSTEM) and performs contextual risk analysis.

Core Principles:
- A requested permission is NOT malware by itself (e.g. CAMERA in a video app is benign).
- Identifies high-risk permission clusters (Banking Trojan, Spyware, SMS Spammer, Dropper).
- Correlates requested permissions with apparent application category where feasible.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# --- Authoritative Android Permission Categories ---

CATEGORY_NORMAL = "NORMAL"
CATEGORY_DANGEROUS = "DANGEROUS"
CATEGORY_SPECIAL = "SPECIAL"
CATEGORY_SIGNATURE = "SIGNATURE"
CATEGORY_UNKNOWN = "UNKNOWN"

class PermissionTier:
    NORMAL = CATEGORY_NORMAL
    DANGEROUS = CATEGORY_DANGEROUS
    SPECIAL = CATEGORY_SPECIAL
    SIGNATURE = CATEGORY_SIGNATURE
    UNKNOWN = CATEGORY_UNKNOWN

# High-interest Android permissions mapped to their protection tiers
DANGEROUS_PERMISSIONS = {
    # SMS / Telephony (High abuse in Banking Trojans & SMS Toll Fraud)
    "android.permission.READ_SMS": "SMS",
    "android.permission.RECEIVE_SMS": "SMS",
    "android.permission.SEND_SMS": "SMS",
    "android.permission.RECEIVE_MMS": "SMS",
    "android.permission.RECEIVE_WAP_PUSH": "SMS",
    "android.permission.READ_PHONE_STATE": "PHONE",
    "android.permission.CALL_PHONE": "PHONE",
    "android.permission.READ_CALL_LOG": "CALL_LOG",
    "android.permission.WRITE_CALL_LOG": "CALL_LOG",
    "android.permission.ADD_VOICEMAIL": "PHONE",
    "android.permission.USE_SIP": "PHONE",
    "android.permission.PROCESS_OUTGOING_CALLS": "PHONE",
    "android.permission.ANSWER_PHONE_CALLS": "PHONE",
    # Personal Identity & Contacts
    "android.permission.READ_CONTACTS": "CONTACTS",
    "android.permission.WRITE_CONTACTS": "CONTACTS",
    "android.permission.GET_ACCOUNTS": "ACCOUNTS",
    # Physical Location
    "android.permission.ACCESS_FINE_LOCATION": "LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION": "LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "LOCATION",
    # Sensors & Recording
    "android.permission.CAMERA": "CAMERA",
    "android.permission.RECORD_AUDIO": "MICROPHONE",
    "android.permission.BODY_SENSORS": "SENSORS",
    # External Storage
    "android.permission.READ_EXTERNAL_STORAGE": "STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE": "STORAGE",
    "android.permission.READ_MEDIA_IMAGES": "STORAGE",
    "android.permission.READ_MEDIA_VIDEO": "STORAGE",
    "android.permission.READ_MEDIA_AUDIO": "STORAGE",
    # Calendar
    "android.permission.READ_CALENDAR": "CALENDAR",
    "android.permission.WRITE_CALENDAR": "CALENDAR",
    # Notifications (Android 13+)
    "android.permission.POST_NOTIFICATIONS": "NOTIFICATIONS",
}

# Special & High-Privilege Capabilities (frequently exploited for overlays, hijacking, or persistence)
SPECIAL_CAPABILITIES = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "ACCESSIBILITY_HIJACK",
    "android.permission.SYSTEM_ALERT_WINDOW": "OVERLAY_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES": "PACKAGE_DROPPER",
    "android.permission.BIND_DEVICE_ADMIN": "DEVICE_ADMINISTRATION",
    "android.permission.PACKAGE_USAGE_STATS": "USAGE_MONITORING",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "FULL_FILESYSTEM",
    "android.permission.QUERY_ALL_PACKAGES": "PACKAGE_ENUMERATION",
    "android.permission.RECEIVE_BOOT_COMPLETED": "AUTOSTART_PERSISTENCE",
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": "BACKGROUND_SURVIVAL",
    "android.permission.USE_FULL_SCREEN_INTENT": "FULL_SCREEN_OVERLAY",
    "android.permission.FOREGROUND_SERVICE": "BACKGROUND_EXECUTION",
    "android.permission.KILL_BACKGROUND_PROCESSES": "TASK_KILLER",
    "android.permission.WRITE_SETTINGS": "SYSTEM_SETTINGS",
}

NORMAL_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.VIBRATE",
    "android.permission.WAKE_LOCK",
    "android.permission.BLUETOOTH",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.NFC",
    "android.permission.EXPAND_STATUS_BAR",
    "android.permission.SET_WALLPAPER",
}

AOSP_DANGEROUS_PERMISSIONS = DANGEROUS_PERMISSIONS
AOSP_SPECIAL_PERMISSIONS = SPECIAL_CAPABILITIES


@dataclass
class CategorizedPermission:
    raw_name: str
    short_name: str
    category: str              # DANGEROUS, SPECIAL, NORMAL, SIGNATURE, UNKNOWN
    group: Optional[str] = None
    description: str = ""
    is_sensitive: bool = False


@dataclass
class PermissionClusterFinding:
    name: str
    severity: str              # critical, high, medium, low
    description: str
    matched_permissions: List[str]
    rule_id: str


@dataclass
class PermissionAnalysisReport:
    total_count: int
    dangerous_count: int
    special_count: int
    normal_count: int
    unknown_count: int
    permissions: List[CategorizedPermission] = field(default_factory=list)
    clusters: List[PermissionClusterFinding] = field(default_factory=list)
    risk_score: int = 0


def clean_permission_name(perm: str) -> str:
    """Strip package qualifiers for display (e.g. android.permission.CAMERA -> CAMERA)."""
    if not perm:
        return ""
    return perm.split(".")[-1]


def categorize_permission(perm: str) -> str:
    """Return category tier for a permission: DANGEROUS, SPECIAL, NORMAL, or UNKNOWN."""
    clean = perm.strip()
    if clean in SPECIAL_CAPABILITIES:
        return CATEGORY_SPECIAL
    if clean in DANGEROUS_PERMISSIONS:
        return CATEGORY_DANGEROUS
    if clean in NORMAL_PERMISSIONS:
        return CATEGORY_NORMAL
    return CATEGORY_UNKNOWN


def is_dangerous_permission(perm: str) -> bool:
    """True if permission is in the AOSP dangerous runtime permission set."""
    return perm.strip() in DANGEROUS_PERMISSIONS


def is_sensitive_permission(perm: str) -> bool:
    """True if permission grants access to sensitive hardware or system capabilities."""
    p = perm.strip()
    return p in DANGEROUS_PERMISSIONS or p in SPECIAL_CAPABILITIES


def detect_permission_clusters(permissions_list: List[str]) -> List[str]:
    """Detect presence of known malicious permission cluster IDs."""
    report = analyze_permissions(permissions_list)
    clusters = []
    for c in report.clusters:
        if c.rule_id == "APK_CLUSTER_BANKING_OVERLAY":
            clusters.append("banking_trojan_overlay")
        elif c.rule_id == "APK_CLUSTER_SURVEILLANCE":
            clusters.append("spyware_surveillance")
        elif c.rule_id == "APK_CLUSTER_DROPPER":
            clusters.append("dropper_capability")
        elif c.rule_id == "APK_CLUSTER_DEVICE_ADMIN":
            clusters.append("device_admin")
        elif c.rule_id == "APK_CLUSTER_SMS_AUTOSTART":
            clusters.append("sms_autostart")
        else:
            clusters.append(c.rule_id.lower())
    return clusters


def assess_contextual_permission_risk(category: str, permissions: List[str]) -> Tuple[int, List[str]]:
    """
    Evaluate requested permissions against the apparent application category.
    Differentiates between legitimate functional requests (e.g. mic in communication app)
    versus anomalous requests (e.g. SMS and mic in a basic utility/calculator app).
    """
    cat = (category or "").lower()
    perms = set(p.strip() for p in permissions)
    anomalous_reasons: List[str] = []
    penalty = 0

    has_sms = bool(perms.intersection({
        "android.permission.READ_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.SEND_SMS",
    }))
    has_mic = "android.permission.RECORD_AUDIO" in perms
    has_cam = "android.permission.CAMERA" in perms
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in perms

    if cat in ("tools", "calculator", "wallpaper", "flashlight", "utility"):
        if has_sms:
            penalty += 25
            anomalous_reasons.append(f"Application categorized as '{cat}' requests sensitive SMS permissions without apparent functional necessity.")
        if has_mic or has_cam:
            penalty += 20
            anomalous_reasons.append(f"Application categorized as '{cat}' requests audio/camera recording permissions.")
        if has_overlay:
            penalty += 20
            anomalous_reasons.append(f"Application categorized as '{cat}' requests overlay window drawing privileges.")

    return min(penalty, 100), anomalous_reasons


def analyze_permissions(permissions_list: List[str], app_context: Optional[str] = None) -> PermissionAnalysisReport:
    """
    Parse a list of requested Android permissions, categorize into tiers,
    and detect known dangerous combination patterns (trojans, spyware, overlays).
    """
    cleaned_set: Set[str] = set()
    categorized: List[CategorizedPermission] = []

    dangerous_count = 0
    special_count = 0
    normal_count = 0
    unknown_count = 0

    for raw in permissions_list:
        p = raw.strip()
        if not p or p in cleaned_set:
            continue
        cleaned_set.add(p)
        short = clean_permission_name(p)

        if p in SPECIAL_CAPABILITIES:
            special_count += 1
            categorized.append(
                CategorizedPermission(
                    raw_name=p,
                    short_name=short,
                    category=CATEGORY_SPECIAL,
                    group=SPECIAL_CAPABILITIES[p],
                    description=f"Special system capability ({SPECIAL_CAPABILITIES[p]})",
                    is_sensitive=True,
                )
            )
        elif p in DANGEROUS_PERMISSIONS:
            dangerous_count += 1
            categorized.append(
                CategorizedPermission(
                    raw_name=p,
                    short_name=short,
                    category=CATEGORY_DANGEROUS,
                    group=DANGEROUS_PERMISSIONS[p],
                    description=f"Runtime dangerous permission affecting {DANGEROUS_PERMISSIONS[p]}",
                    is_sensitive=True,
                )
            )
        elif p in NORMAL_PERMISSIONS:
            normal_count += 1
            categorized.append(
                CategorizedPermission(
                    raw_name=p,
                    short_name=short,
                    category=CATEGORY_NORMAL,
                    group="NORMAL",
                    description="Standard API access permission with minimal system risk",
                    is_sensitive=False,
                )
            )
        else:
            unknown_count += 1
            categorized.append(
                CategorizedPermission(
                    raw_name=p,
                    short_name=short,
                    category=CATEGORY_UNKNOWN,
                    group="CUSTOM_OR_VENDOR",
                    description="Custom or vendor-defined permission string",
                    is_sensitive=False,
                )
            )

    # --- Suspicious Combination / Cluster Analysis ---
    clusters: List[PermissionClusterFinding] = []
    base_risk = 0

    has_accessibility = "android.permission.BIND_ACCESSIBILITY_SERVICE" in cleaned_set
    has_overlay = "android.permission.SYSTEM_ALERT_WINDOW" in cleaned_set
    has_install_pkgs = "android.permission.REQUEST_INSTALL_PACKAGES" in cleaned_set
    has_device_admin = "android.permission.BIND_DEVICE_ADMIN" in cleaned_set

    has_read_sms = "android.permission.READ_SMS" in cleaned_set
    has_receive_sms = "android.permission.RECEIVE_SMS" in cleaned_set
    has_send_sms = "android.permission.SEND_SMS" in cleaned_set
    has_sms = has_read_sms or has_receive_sms or has_send_sms

    has_contacts = "android.permission.READ_CONTACTS" in cleaned_set
    has_audio = "android.permission.RECORD_AUDIO" in cleaned_set
    has_camera = "android.permission.CAMERA" in cleaned_set
    has_location = "android.permission.ACCESS_FINE_LOCATION" in cleaned_set or "android.permission.ACCESS_COARSE_LOCATION" in cleaned_set
    has_net = "android.permission.INTERNET" in cleaned_set
    has_boot = "android.permission.RECEIVE_BOOT_COMPLETED" in cleaned_set

    # 1. Banking Trojan / Fake Token Interceptor Cluster
    # Accessibility + Overlay + SMS/Network is the primary signature of Anatsa, SharkBot, Teabot, FluBot
    if has_accessibility and has_overlay:
        matched = ["android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.SYSTEM_ALERT_WINDOW"]
        if has_sms:
            matched.append("SMS")
        base_risk += 50
        clusters.append(
            PermissionClusterFinding(
                name="Banking Trojan Overlay & Interception Cluster",
                severity="critical",
                description="Requests both Accessibility Service and System Alert Window (Overlay). This combination enables full UI observation, keystroke interception, and deceptive overlay screen creation (typical of Android banking malware).",
                matched_permissions=matched,
                rule_id="APK_CLUSTER_BANKING_OVERLAY",
            )
        )
    elif has_overlay and has_sms:
        base_risk += 35
        clusters.append(
            PermissionClusterFinding(
                name="Overlay and SMS Interception Cluster",
                severity="high",
                description="Combines screen drawing overlays with SMS access, enabling fake login overlays while silently reading 2FA SMS tokens.",
                matched_permissions=["android.permission.SYSTEM_ALERT_WINDOW", "SMS Permissions"],
                rule_id="APK_CLUSTER_OVERLAY_SMS",
            )
        )

    # 2. Spyware / Surveillance Cluster (Microphone + Camera + Location + Contacts + Network)
    surveillance_perms = []
    if has_audio: surveillance_perms.append("RECORD_AUDIO")
    if has_camera: surveillance_perms.append("CAMERA")
    if has_location: surveillance_perms.append("LOCATION")
    if has_contacts: surveillance_perms.append("READ_CONTACTS")

    if len(surveillance_perms) >= 3 and has_net:
        base_risk += 35
        clusters.append(
            PermissionClusterFinding(
                name="Surveillance & Data Exfiltration Cluster",
                severity="high",
                description="Simultaneously requests access to microphone, camera, physical location, and contacts with internet transmission capabilities.",
                matched_permissions=surveillance_perms,
                rule_id="APK_CLUSTER_SURVEILLANCE",
            )
        )

    # 3. Silent Dropper / Secondary Payload Installer
    if has_install_pkgs and has_net:
        base_risk += 25
        clusters.append(
            PermissionClusterFinding(
                name="Secondary APK Dropper Capability",
                severity="medium",
                description="Requests permission to install additional Android packages from the internet without user Play Store review.",
                matched_permissions=["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
                rule_id="APK_CLUSTER_DROPPER",
            )
        )

    # 4. Device Admin Lockout Risk
    if has_device_admin:
        base_risk += 30
        clusters.append(
            PermissionClusterFinding(
                name="Device Administrator Binding",
                severity="high",
                description="Requests Device Administrator privileges, which can prevent the user from uninstalling the application or allow remote device wipe/lockout.",
                matched_permissions=["android.permission.BIND_DEVICE_ADMIN"],
                rule_id="APK_CLUSTER_DEVICE_ADMIN",
            )
        )

    # 5. Background Autostart & SMS Toll Fraud
    if has_send_sms and has_boot:
        base_risk += 25
        clusters.append(
            PermissionClusterFinding(
                name="Autostart SMS Dispatcher",
                severity="medium",
                description="Application can transmit SMS messages in the background automatically upon device boot.",
                matched_permissions=["android.permission.SEND_SMS", "android.permission.RECEIVE_BOOT_COMPLETED"],
                rule_id="APK_CLUSTER_SMS_AUTOSTART",
            )
        )

    # Add marginal risk for sensitive permissions count
    base_risk += min(dangerous_count * 3, 25)
    base_risk += min(special_count * 6, 25)

    capped_risk = min(max(base_risk, 0), 100)

    return PermissionAnalysisReport(
        total_count=len(cleaned_set),
        dangerous_count=dangerous_count,
        special_count=special_count,
        normal_count=normal_count,
        unknown_count=unknown_count,
        permissions=categorized,
        clusters=clusters,
        risk_score=capped_risk,
    )
