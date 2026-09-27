"""
ScamBuster — Permission to Static API Mapping & Correlation Engine (Phase 08)

Maps requested permissions to static Dalvik bytecode method and class references.
Enables evidentiary correlation between declared manifest capabilities and actual code references.

CRITICAL PRINCIPLES:
- Static API reference != Runtime execution proof (an app may contain an unused library or check permissions before calling).
- Correlating a requested permission with an actual API reference increases confidence that the capability is intentionally implemented.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

# Mapping of Permission Category / Specific Permission to Dalvik Bytecode Patterns
PERMISSION_API_PATTERNS: Dict[str, List[bytes]] = {
    "android.permission.CAMERA": [
        b"android/hardware/Camera",
        b"android/hardware/camera2",
        b"androidx/camera/core",
        b"takePicture",
        b"openCamera",
        b"setPreviewDisplay",
    ],
    "android.permission.RECORD_AUDIO": [
        b"android/media/AudioRecord",
        b"android/media/MediaRecorder",
        b"AudioSource",
        b"startRecording",
        b"setAudioSource",
    ],
    "android.permission.ACCESS_FINE_LOCATION": [
        b"android/location/LocationManager",
        b"com/google/android/gms/location/FusedLocationProviderClient",
        b"requestLocationUpdates",
        b"getLastKnownLocation",
        b"GPS_PROVIDER",
    ],
    "android.permission.ACCESS_COARSE_LOCATION": [
        b"android/location/LocationManager",
        b"NETWORK_PROVIDER",
        b"getLastKnownLocation",
    ],
    "android.permission.ACCESS_BACKGROUND_LOCATION": [
        b"requestBackgroundLocationUpdates",
        b"ACCESS_BACKGROUND_LOCATION",
    ],
    "android.permission.READ_CONTACTS": [
        b"android/provider/ContactsContract",
        b"content://com.android.contacts",
        b"ContactsContract$CommonDataKinds$Phone",
    ],
    "android.permission.READ_SMS": [
        b"content://sms",
        b"content://sms/inbox",
        b"android/telephony/SmsMessage",
        b"createFromPdu",
    ],
    "android.permission.SEND_SMS": [
        b"android/telephony/SmsManager",
        b"sendTextMessage",
        b"sendMultipartTextMessage",
    ],
    "android.permission.READ_PHONE_STATE": [
        b"android/telephony/TelephonyManager",
        b"getDeviceId",
        b"getImei",
        b"getSimSerialNumber",
        b"getSubscriberId",
        b"getLine1Number",
    ],
    "android.permission.READ_CALL_LOG": [
        b"android/provider/CallLog",
        b"content://call_log",
    ],
    "android.permission.BIND_ACCESSIBILITY_SERVICE": [
        b"android/accessibilityservice/AccessibilityService",
        b"android/view/accessibility/AccessibilityNodeInfo",
        b"performAction",
        b"findAccessibilityNodeInfosByViewId",
        b"getRootInActiveWindow",
    ],
    "android.permission.SYSTEM_ALERT_WINDOW": [
        b"TYPE_APPLICATION_OVERLAY",
        b"TYPE_SYSTEM_ALERT",
        b"android/provider/Settings;->canDrawOverlays",
        b"ACTION_MANAGE_OVERLAY_PERMISSION",
    ],
    "android.permission.BIND_DEVICE_ADMIN": [
        b"android/app/admin/DevicePolicyManager",
        b"android/app/admin/DeviceAdminReceiver",
        b"lockNow",
        b"wipeData",
        b"resetPassword",
    ],
    "android.permission.REQUEST_INSTALL_PACKAGES": [
        b"android/content/pm/PackageInstaller",
        b"ACTION_INSTALL_PACKAGE",
        b"application/vnd.android.package-archive",
    ],
    "android.permission.PACKAGE_USAGE_STATS": [
        b"android/app/usage/UsageStatsManager",
        b"queryUsageStats",
        b"queryEvents",
    ],
}


@dataclass
class PermissionApiCorrelation:
    permission: str
    status: str                         # "CORRELATED", "PERMISSION_ONLY", "API_ONLY"
    matched_apis: List[str] = field(default_factory=list)
    confidence: str = "MEDIUM"          # "HIGH", "MEDIUM", "LOW"
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "permission": self.permission,
            "status": self.status,
            "matched_apis": self.matched_apis,
            "confidence": self.confidence,
            "explanation": self.explanation,
        }


def find_apis_in_dex_content(dex_data: bytes, perm_patterns: List[bytes]) -> List[str]:
    """Search raw DEX bytecode bytes for target API signature bytes."""
    matched = []
    for pat in perm_patterns:
        if pat in dex_data:
            matched.append(pat.decode("ascii", errors="ignore"))
    return matched


def correlate_permissions_with_apis(
    requested_permissions: List[str],
    dex_data: Optional[bytes] = None,
    dex_indicators: Optional[Dict[str, List[str]]] = None,
) -> Tuple[List[PermissionApiCorrelation], int]:
    """
    Correlate requested permissions with static bytecode API indicators.
    Returns:
        (correlations_list, total_correlated_count)
    """
    correlations: List[PermissionApiCorrelation] = []
    correlated_count = 0
    requested_set = set(p.strip() for p in requested_permissions)

    for perm, patterns in PERMISSION_API_PATTERNS.items():
        is_requested = perm in requested_set
        matched_apis: List[str] = []

        # 1. Search raw DEX bytes if provided
        if dex_data:
            matched_apis.extend(find_apis_in_dex_content(dex_data, patterns))

        # 2. Check pre-extracted DEX indicators from Phase 07 analyzer
        if dex_indicators:
            for ind_list in dex_indicators.values():
                for ind in ind_list:
                    ind_lower = ind.lower()
                    for p in patterns:
                        p_str = p.decode("ascii", errors="ignore").lower()
                        if p_str in ind_lower:
                            matched_apis.append(ind)

        matched_apis = sorted(list(set(matched_apis)))

        if is_requested and matched_apis:
            correlated_count += 1
            correlations.append(
                PermissionApiCorrelation(
                    permission=perm,
                    status="CORRELATED",
                    matched_apis=matched_apis,
                    confidence="HIGH",
                    explanation=(
                        f"The application requests '{perm.split('.')[-1]}' and static inspection "
                        f"identifies corresponding API references in the APK bytecode ({', '.join(matched_apis[:3])}). "
                        f"Note: this confirms code reference presence, not actual runtime invocation."
                    ),
                )
            )
        elif is_requested and not matched_apis:
            correlations.append(
                PermissionApiCorrelation(
                    permission=perm,
                    status="PERMISSION_ONLY",
                    matched_apis=[],
                    confidence="MEDIUM",
                    explanation=(
                        f"The application requests '{perm.split('.')[-1]}', but obvious corresponding "
                        f"static API references were not located in primary DEX string tables."
                    ),
                )
            )
        elif not is_requested and matched_apis:
            correlations.append(
                PermissionApiCorrelation(
                    permission=perm,
                    status="API_ONLY",
                    matched_apis=matched_apis,
                    confidence="LOW",
                    explanation=(
                        f"Bytecode contains references to APIs typically protected by '{perm.split('.')[-1]}', "
                        f"though the permission was not explicitly declared in AndroidManifest.xml. "
                        f"May represent third-party SDK dependencies or conditional runtime checks."
                    ),
                )
            )

    return correlations, correlated_count
