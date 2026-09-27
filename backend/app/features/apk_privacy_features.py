"""
ScamBuster ML — Android APK Privacy Feature Engineering Layer (Phase 08)

Defines authoritative 16 privacy and capability features extracted from Android packages.
Ensures consistency between dataset preparation, training, and inference.

Feature Version: privacy-feature-v1
"""

from typing import Any, Dict, List, Union

PRIVACY_FEATURE_VERSION = "privacy-feature-v1"
FEATURE_VERSION = PRIVACY_FEATURE_VERSION

PRIVACY_FEATURE_NAMES = [
    "permission_count",
    "sensitive_permission_count",
    "high_impact_permission_count",
    "permission_category_count",
    "permission_combination_count",
    "api_permission_match_count",
    "context_mismatch_score",
    "exported_component_count",
    "service_count",
    "receiver_count",
    "has_accessibility_indicator",
    "has_overlay_indicator",
    "has_device_admin_indicator",
    "has_boot_autostart_indicator",
    "has_sms_capability",
    "has_location_capability",
]


def extract_privacy_features(privacy_res: Any) -> Dict[str, Union[int, float]]:
    """
    Extract 16 numerical features from an ApkPrivacyAnalysisResult or compatible dictionary.
    """
    if isinstance(privacy_res, dict):
        return {
            "permission_count": privacy_res.get("permission_count", privacy_res.get("total_requested_count", 0)),
            "sensitive_permission_count": privacy_res.get("sensitive_permission_count", privacy_res.get("sensitive_permissions_count", 0)),
            "high_impact_permission_count": privacy_res.get("high_impact_permission_count", privacy_res.get("high_impact_count", 0)),
            "permission_category_count": privacy_res.get("permission_category_count", len(privacy_res.get("categories_requested", []))),
            "permission_combination_count": privacy_res.get("permission_combination_count", len(privacy_res.get("combination_findings", []))),
            "api_permission_match_count": privacy_res.get("api_permission_match_count", 0),
            "context_mismatch_score": privacy_res.get("context_mismatch_score", privacy_res.get("context_analysis", {}).get("mismatch_score", 0)),
            "exported_component_count": privacy_res.get("exported_component_count", 0),
            "service_count": privacy_res.get("service_count", 0),
            "receiver_count": privacy_res.get("receiver_count", 0),
            "has_accessibility_indicator": 1 if privacy_res.get("has_accessibility_indicator") else 0,
            "has_overlay_indicator": 1 if privacy_res.get("has_overlay_indicator") else 0,
            "has_device_admin_indicator": 1 if privacy_res.get("has_device_admin_indicator") else 0,
            "has_boot_autostart_indicator": 1 if privacy_res.get("has_boot_autostart_indicator") else 0,
            "has_sms_capability": 1 if privacy_res.get("has_sms_capability") else 0,
            "has_location_capability": 1 if privacy_res.get("has_location_capability") else 0,
        }

    matched_apis = sum(1 for c in privacy_res.api_correlations if c.get("status") == "CORRELATED")
    p_details = {p.get("short_name") for p in privacy_res.permissions_detail}

    return {
        "permission_count": privacy_res.total_requested_count,
        "sensitive_permission_count": privacy_res.sensitive_permissions_count,
        "high_impact_permission_count": privacy_res.high_impact_count,
        "permission_category_count": len(privacy_res.categories_requested),
        "permission_combination_count": len(privacy_res.combination_findings),
        "api_permission_match_count": matched_apis,
        "context_mismatch_score": privacy_res.context_analysis.get("mismatch_score", 0),
        "exported_component_count": 0,
        "service_count": len([b for b in privacy_res.background_capabilities if "service" in b]),
        "receiver_count": len([b for b in privacy_res.background_capabilities if "receiver" in b]),
        "has_accessibility_indicator": 1 if "BIND_ACCESSIBILITY_SERVICE" in p_details else 0,
        "has_overlay_indicator": 1 if "SYSTEM_ALERT_WINDOW" in p_details else 0,
        "has_device_admin_indicator": 1 if "BIND_DEVICE_ADMIN" in p_details else 0,
        "has_boot_autostart_indicator": 1 if any("boot" in b.lower() for b in privacy_res.background_capabilities) else 0,
        "has_sms_capability": 1 if any("SMS" in c for c in privacy_res.categories_requested) else 0,
        "has_location_capability": 1 if any("LOCATION" in c for c in privacy_res.categories_requested) else 0,
    }


def extract_privacy_feature_vector(privacy_res: Any) -> List[float]:
    """
    Extract a deterministic ordered list of float features suitable for ML privacy classifiers.
    Order matches PRIVACY_FEATURE_NAMES exactly.
    """
    feat_dict = extract_privacy_features(privacy_res)
    return [float(feat_dict[k]) for k in PRIVACY_FEATURE_NAMES]
