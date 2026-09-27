"""
ScamBuster — Android Version Awareness & API Level Semantics (Phase 08)

Maintains version-dependent behavior differences across Android releases.
Prevents outdated assumptions (e.g. treating READ_EXTERNAL_STORAGE as full device access on Android 13+).
"""

from typing import Dict, List, Optional, Tuple

# Key Android API Milestones
API_LEVEL_NAMES: Dict[int, Tuple[str, str]] = {
    21: ("5.0", "Lollipop"),
    22: ("5.1", "Lollipop MR1"),
    23: ("6.0", "Marshmallow"),        # Runtime permissions introduced
    24: ("7.0", "Nougat"),
    25: ("7.1", "Nougat MR1"),
    26: ("8.0", "Oreo"),               # Background execution limits
    27: ("8.1", "Oreo MR1"),
    28: ("9.0", "Pie"),                # Foreground service permission
    29: ("10.0", "Q"),                 # ACCESS_BACKGROUND_LOCATION, Scoped Storage preview
    30: ("11.0", "R"),                 # MANAGE_EXTERNAL_STORAGE, one-time permissions
    31: ("12.0", "S"),                 # Approximate location, BLUETOOTH_SCAN/CONNECT
    32: ("12.0L", "Sv2"),
    33: ("13.0", "Tiramisu"),          # POST_NOTIFICATIONS, Granular Media permissions
    34: ("14.0", "UpsideDownCake"),    # READ_MEDIA_VISUAL_USER_SELECTED
    35: ("15.0", "VanillaIceCream"),
}

# Version boundaries
RUNTIME_PERMISSIONS_API_LEVEL = 23      # Android 6.0 Marshmallow
BACKGROUND_LOCATION_API_LEVEL = 29      # Android 10 Q
SCOPED_STORAGE_ENFORCED_API_LEVEL = 30  # Android 11 R
GRANULAR_MEDIA_API_LEVEL = 33           # Android 13 Tiramisu
NOTIFICATION_RUNTIME_API_LEVEL = 33     # Android 13 Tiramisu
SELECTED_MEDIA_API_LEVEL = 34           # Android 14 UpsideDownCake


def parse_sdk_version(sdk_str: Optional[str]) -> Optional[int]:
    """Parse SDK version string to integer safely."""
    if not sdk_str:
        return None
    try:
        return int(str(sdk_str).strip())
    except (ValueError, TypeError):
        return None


def get_android_version_display(api_level: Optional[int]) -> str:
    """Format human-readable Android release name from API level."""
    if not api_level:
        return "Unknown Android Version"
    if api_level in API_LEVEL_NAMES:
        ver, code = API_LEVEL_NAMES[api_level]
        return f"Android {ver} ({code}, API {api_level})"
    if api_level > 35:
        return f"Android 15+ (API {api_level})"
    return f"Legacy Android (API {api_level})"


def is_runtime_permission_at_target(permission: str, target_sdk: Optional[int], is_dangerous: bool) -> bool:
    """
    Check if a permission requires explicit runtime user consent on the target SDK.
    Runtime permissions were introduced in API 23 (Android 6.0).
    """
    if not is_dangerous:
        return False
    if target_sdk is None:
        return True  # Default to modern runtime semantics
    return target_sdk >= RUNTIME_PERMISSIONS_API_LEVEL


def get_storage_permission_model(target_sdk: Optional[int]) -> Dict[str, str]:
    """
    Explain storage permission semantics based on target SDK version.
    """
    if target_sdk is None or target_sdk >= GRANULAR_MEDIA_API_LEVEL:
        return {
            "model": "Granular Media & Scoped Storage",
            "description": (
                "On Android 13+ (API 33+), READ_EXTERNAL_STORAGE is superseded by granular "
                "media permissions (READ_MEDIA_IMAGES, READ_MEDIA_VIDEO, READ_MEDIA_AUDIO). "
                "Legacy storage permissions grant no direct broad access."
            ),
        }
    if target_sdk >= SCOPED_STORAGE_ENFORCED_API_LEVEL:
        return {
            "model": "Scoped Storage (Android 11-12)",
            "description": (
                "Scoped Storage is strictly enforced. Applications only access their own sandboxed "
                "directory and media collections, unless granted MANAGE_EXTERNAL_STORAGE."
            ),
        }
    return {
        "model": "Legacy External Storage (Pre-Android 11)",
        "description": (
            "Legacy broad external storage access. Granted permissions allow reading/writing "
            "shared files on the SD card / external storage partition."
        ),
    }


def is_notification_runtime_required(target_sdk: Optional[int]) -> bool:
    """
    Returns True if POST_NOTIFICATIONS is an explicit runtime permission on this target SDK.
    Prior to Android 13 (API 33), notifications were enabled by default.
    """
    if target_sdk is None:
        return True
    return target_sdk >= NOTIFICATION_RUNTIME_API_LEVEL
