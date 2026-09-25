"""
ScamBuster Heuristic Cyber Analyzer — Android APK & Permission Analysis

Deterministic cybersecurity analysis detecting:
- Critical Android permissions abused by mobile banking trojans & spyware
- Toxic permission combinations (e.g. Accessibility + Window Overlay = Trojan signature)
- SMS interception and OTP exfiltration capabilities
- Silent dropper and secondary payload installation rights
- Package name spoofing and system service disguise
"""

import re
from typing import Any, Dict, List, Optional

# Permissions mapped to MITRE ATT&CK Mobile threat categories
HIGH_RISK_PERMISSIONS = {
    "android.permission.BIND_ACCESSIBILITY_SERVICE": {
        "severity": "CRITICAL",
        "name": "Accessibility Service Binding",
        "description": "Permits programmatic UI interaction, keystroke logging, and prevention of app uninstallation. Prime indicator of modern Android Banking Trojans (e.g., Anatsa, SharkBot).",
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "severity": "HIGH",
        "name": "System Alert Overlay",
        "description": "Allows drawing windows over legitimate apps to display deceptive fake login screens (Overlay Attack).",
    },
    "android.permission.RECEIVE_SMS": {
        "severity": "HIGH",
        "name": "SMS Message Interception",
        "description": "Can intercept incoming SMS messages, commonly utilized to steal bank 2FA/OTP authentication codes.",
    },
    "android.permission.READ_SMS": {
        "severity": "HIGH",
        "name": "SMS Message Reading",
        "description": "Grants unrestricted access to existing SMS inbox messages and sensitive one-time passcodes.",
    },
    "android.permission.SEND_SMS": {
        "severity": "HIGH",
        "name": "Background SMS Transmission",
        "description": "Allows sending SMS without user confirmation, potentially generating high charges via premium-rate SMS numbers.",
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "severity": "HIGH",
        "name": "Arbitrary Package Installer (Dropper Vector)",
        "description": "Allows downloading and prompting installation of external APKs, a hallmark characteristic of dropper malware.",
    },
    "android.permission.BIND_DEVICE_ADMIN": {
        "severity": "CRITICAL",
        "name": "Device Administrator Authority",
        "description": "Grants elevated device policies, often abused by ransomware to lock device screens and block deletion.",
    },
    "android.permission.RECORD_AUDIO": {
        "severity": "MEDIUM",
        "name": "Microphone Audio Recording",
        "description": "Permits unauthorized background audio surveillance without persistent user notification.",
    },
    "android.permission.ACCESS_BACKGROUND_LOCATION": {
        "severity": "MEDIUM",
        "name": "Persistent Background Geolocation",
        "description": "Tracks victim physical coordinates continuously even when the application is closed.",
    },
    "android.permission.READ_CALL_LOG": {
        "severity": "MEDIUM",
        "name": "Call History Access",
        "description": "Harvests contact call logs and metadata.",
    },
}

SUSPICIOUS_PACKAGE_KEYWORDS = [
    "update", "security", "patch", "cleaner", "booster", "battery",
    "whatsapp_gold", "free_crypto", "flash", "antivirus_free"
]


def analyze_apk(
    package_name: str,
    permissions: List[str],
    app_name: Optional[str] = None
) -> Dict[str, Any]:
    """
    Perform deep deterministic static security analysis on Android application permissions and metadata.
    Returns heuristic score (0-100), threat indicators, and mobile security profile.
    """
    indicators: List[Dict[str, Any]] = []
    score = 0

    norm_permissions = {p.strip() for p in permissions}

    # 1. Single Critical Permission Checks
    for perm_name, meta in HIGH_RISK_PERMISSIONS.items():
        # Check both full name and shorthand (e.g. BIND_ACCESSIBILITY_SERVICE)
        short_name = perm_name.split(".")[-1]
        if perm_name in norm_permissions or short_name in norm_permissions:
            if meta["severity"] == "CRITICAL":
                score += 35
            elif meta["severity"] == "HIGH":
                score += 25
            else:
                score += 15

            indicators.append({
                "name": meta["name"],
                "severity": meta["severity"],
                "description": meta["description"],
                "evidence": perm_name,
            })

    # 2. Toxic Combinations Analysis
    has_accessibility = any(
        "ACCESSIBILITY" in p.upper() for p in norm_permissions
    )
    has_overlay = any(
        "SYSTEM_ALERT_WINDOW" in p.upper() for p in norm_permissions
    )
    has_sms = any(
        "SMS" in p.upper() for p in norm_permissions
    )
    has_internet = any(
        "INTERNET" in p.upper() for p in norm_permissions
    )
    has_installer = any(
        "INSTALL_PACKAGES" in p.upper() for p in norm_permissions
    )

    # Combo A: Banking Trojan Overlay + Keystroke (Accessibility + Overlay)
    if has_accessibility and has_overlay:
        score += 35
        indicators.append({
            "name": "Banking Trojan Signature (Accessibility + Overlay)",
            "severity": "CRITICAL",
            "description": "Combination of Accessibility Service and System Alert Window allows the app to present spoofed credential dialogs and auto-approve permissions.",
            "evidence": "BIND_ACCESSIBILITY_SERVICE + SYSTEM_ALERT_WINDOW",
        })

    # Combo B: OTP Exfiltration (SMS + Internet)
    if has_sms and has_internet:
        score += 20
        indicators.append({
            "name": "OTP Exfiltration Vector (SMS + Network)",
            "severity": "HIGH",
            "description": "App possesses both SMS read/receive capability and network egress, enabling silent extraction of two-factor authentication tokens.",
            "evidence": "SMS Access + INTERNET",
        })

    # Combo C: Dropper Payload Vector (Install Packages + Internet)
    if has_installer and has_internet:
        score += 25
        indicators.append({
            "name": "Malware Dropper Vector (Dynamic Package Installation)",
            "severity": "HIGH",
            "description": "App can download and trigger installation of arbitrary APK packages outside of official app stores.",
            "evidence": "REQUEST_INSTALL_PACKAGES + INTERNET",
        })

    # 3. Package Name Disguise Heuristics
    pkg_lower = package_name.lower()
    for kw in SUSPICIOUS_PACKAGE_KEYWORDS:
        if kw in pkg_lower and ("google" in pkg_lower or "android" in pkg_lower):
            score += 25
            indicators.append({
                "name": "System Service Disguise in Package Name",
                "severity": "HIGH",
                "description": f"The package name '{package_name}' disguises itself as an official Google or Android system update utility.",
                "evidence": package_name,
            })
            break

    # 4. Excessive Dangerous Permission Density
    if len(indicators) >= 5:
        score += 20
        indicators.append({
            "name": "Abnormal Permission Footprint",
            "severity": "MEDIUM",
            "description": f"Application requests an unusually dense cluster of {len(norm_permissions)} permissions containing multiple privileged capabilities.",
            "evidence": f"{len(norm_permissions)} total permissions requested",
        })

    capped_score = min(max(score, 0), 100)

    return {
        "score": capped_score,
        "indicators": indicators,
        "details": {
            "package_name": package_name,
            "app_name": app_name,
            "total_permissions_requested": len(norm_permissions),
            "threat_indicator_count": len(indicators),
        }
    }
