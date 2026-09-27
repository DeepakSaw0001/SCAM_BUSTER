"""
ScamBuster ML — Android APK Feature Engineering Layer (Phase 07)

Defines the authoritative 26 static features extracted from Android APK packages.
Ensures 100% feature consistency between dataset preparation, model training,
and production inference.

Feature Version: apk-feature-v1
"""

from typing import Any, Dict, List, Union

APK_FEATURE_VERSION = "apk-feature-v1"

APK_FEATURE_NAMES = [
    "package_name_length",
    "total_permission_count",
    "dangerous_permission_count",
    "special_permission_count",
    "has_sms_permission",
    "has_accessibility_permission",
    "has_overlay_permission",
    "has_install_packages_permission",
    "has_device_admin_permission",
    "has_surveillance_cluster",
    "has_banking_overlay_cluster",
    "activity_count",
    "service_count",
    "receiver_count",
    "provider_count",
    "exported_component_count",
    "dex_count",
    "total_dex_size_kb",
    "has_dynamic_loading",
    "has_reflection",
    "has_command_execution",
    "native_library_count",
    "is_debug_certificate",
    "embedded_url_count",
    "suspicious_url_count",
    "file_size_kb",
]


def extract_features_from_apk_result(analysis: Any) -> Dict[str, Union[int, float]]:
    """
    Extract a dictionary of numerical features from an ApkStaticAnalysisResult instance
    or a compatible dictionary.
    """
    if isinstance(analysis, dict):
        return {
            "package_name_length": len(analysis.get("package_name", "")),
            "total_permission_count": analysis.get("permission_count", 0),
            "dangerous_permission_count": analysis.get("dangerous_permission_count", 0),
            "special_permission_count": analysis.get("sensitive_permission_count", 0),
            "has_sms_permission": 1 if analysis.get("has_sms_permission") else 0,
            "has_accessibility_permission": 1 if analysis.get("has_accessibility_permission") else 0,
            "has_overlay_permission": 1 if analysis.get("has_overlay_permission") else 0,
            "has_install_packages_permission": 1 if analysis.get("has_install_packages_permission") else 0,
            "has_device_admin_permission": 1 if analysis.get("has_device_admin_permission") else 0,
            "has_surveillance_cluster": 1 if analysis.get("has_surveillance_cluster") else 0,
            "has_banking_overlay_cluster": 1 if analysis.get("has_banking_overlay_cluster") else 0,
            "activity_count": analysis.get("activity_count", 0),
            "service_count": analysis.get("service_count", 0),
            "receiver_count": analysis.get("receiver_count", 0),
            "provider_count": analysis.get("provider_count", 0),
            "exported_component_count": analysis.get("exported_component_count", 0),
            "dex_count": analysis.get("dex_count", 1),
            "total_dex_size_kb": analysis.get("total_dex_size_kb", 500.0),
            "has_dynamic_loading": 1 if analysis.get("has_dynamic_loading") else 0,
            "has_reflection": 1 if analysis.get("has_reflection") else 0,
            "has_command_execution": 1 if analysis.get("has_command_execution") else 0,
            "native_library_count": analysis.get("native_library_count", 0),
            "is_debug_certificate": 1 if analysis.get("is_debug_certificate") else 0,
            "embedded_url_count": analysis.get("url_count", analysis.get("embedded_url_count", 0)),
            "suspicious_url_count": analysis.get("suspicious_url_count", 0),
            "file_size_kb": analysis.get("file_size_kb", 1024.0),
        }

    perms = analysis.permission_report
    dex = analysis.dex_analysis
    clusters = {c.rule_id for c in perms.clusters}

    has_sms = 1 if any(p.group == "SMS" for p in perms.permissions) else 0
    has_access = 1 if any(p.raw_name == "android.permission.BIND_ACCESSIBILITY_SERVICE" for p in perms.permissions) else 0
    has_overlay = 1 if any(p.raw_name == "android.permission.SYSTEM_ALERT_WINDOW" for p in perms.permissions) else 0
    has_install = 1 if any(p.raw_name == "android.permission.REQUEST_INSTALL_PACKAGES" for p in perms.permissions) else 0
    has_admin = 1 if any(p.raw_name == "android.permission.BIND_DEVICE_ADMIN" for p in perms.permissions) else 0

    has_surv = 1 if "APK_CLUSTER_SURVEILLANCE" in clusters else 0
    has_bank = 1 if "APK_CLUSTER_BANKING_OVERLAY" in clusters else 0

    has_dyn = 1 if len(dex.dynamic_code_loading_indicators) > 0 else 0
    has_refl = 1 if len(dex.reflection_indicators) > 0 else 0
    has_cmd = 1 if len(dex.command_execution_indicators) > 0 else 0

    suspicious_urls = sum(1 for u in analysis.embedded_urls if getattr(u, "risk_score", 0) >= 40)

    return {
        "package_name_length": len(analysis.package_name),
        "total_permission_count": perms.total_count,
        "dangerous_permission_count": perms.dangerous_count,
        "special_permission_count": perms.special_count,
        "has_sms_permission": has_sms,
        "has_accessibility_permission": has_access,
        "has_overlay_permission": has_overlay,
        "has_install_packages_permission": has_install,
        "has_device_admin_permission": has_admin,
        "has_surveillance_cluster": has_surv,
        "has_banking_overlay_cluster": has_bank,
        "activity_count": analysis.activity_count,
        "service_count": analysis.service_count,
        "receiver_count": analysis.receiver_count,
        "provider_count": analysis.provider_count,
        "exported_component_count": analysis.exported_component_count,
        "dex_count": dex.dex_count,
        "total_dex_size_kb": round(dex.total_dex_size_bytes / 1024.0, 2),
        "has_dynamic_loading": has_dyn,
        "has_reflection": has_refl,
        "has_command_execution": has_cmd,
        "native_library_count": analysis.native_library_count,
        "is_debug_certificate": 1 if analysis.certificate.is_debug_certificate else 0,
        "embedded_url_count": len(analysis.embedded_urls),
        "suspicious_url_count": suspicious_urls,
        "file_size_kb": round(analysis.file_size_bytes / 1024.0, 2),
    }


def extract_apk_feature_vector(analysis: Any) -> List[float]:
    """
    Extract a deterministic ordered list of float features suitable for ML classifiers.
    Order matches APK_FEATURE_NAMES exactly.
    """
    feat_dict = extract_features_from_apk_result(analysis)
    return [float(feat_dict[k]) for k in APK_FEATURE_NAMES]
