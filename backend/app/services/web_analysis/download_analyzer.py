"""
Download & Payload Risk Analyzer

Safely detects and analyzes file downloads initiated via HTTP Content-Disposition headers,
MIME types, file extensions, and magic-byte signatures.

Enforces size caps, computes SHA-256, categorizes high-impact file types
(APK, Windows Executables, Scripts), and routes APK downloads into the
Phase 07/08 static security and privacy pipeline without code execution.
"""

import hashlib
import os
import re
import tempfile
from typing import Any, Dict, Optional, Tuple
import urllib.parse
from app.services.web_analysis.limits import MAX_DOWNLOAD_SIZE

# Magic byte signatures
MAGIC_BYTES = {
    b"PK\x03\x04": "ZIP/APK",
    b"MZ": "WINDOWS_PE_EXE",
    b"%PDF-": "PDF",
    b"\x7fELF": "LINUX_ELF",
    b"MSCF": "CABINET",
    b"Rar!\x1a\x07": "RAR",
    b"7z\xbc\xaf\x27\x1c": "7ZIP",
}

# Dangerous / high-impact extensions
DANGEROUS_EXTENSIONS = {
    ".exe": "EXE",
    ".msi": "EXE",
    ".dll": "EXE",
    ".scr": "EXE",
    ".bat": "SCRIPT",
    ".cmd": "SCRIPT",
    ".ps1": "SCRIPT",
    ".vbs": "SCRIPT",
    ".sh": "SCRIPT",
    ".apk": "APK",
}


def detect_file_category_from_mime(mime: str) -> Optional[str]:
    """
    Map MIME content-type to high-level file category.
    """
    m = mime.lower().split(";")[0].strip()
    if m == "application/vnd.android.package-archive":
        return "APK"
    if m in ("application/x-msdownload", "application/x-msdos-program", "application/x-dosexec"):
        return "EXE"
    if m == "application/pdf":
        return "PDF"
    if m in ("application/zip", "application/x-zip-compressed", "application/x-rar-compressed", "application/x-7z-compressed"):
        return "ARCHIVE"
    if m.startswith("image/"):
        return "IMAGE"
    if m.startswith("text/html"):
        return "HTML"
    if m.startswith("text/"):
        return "TEXT"
    return None


def extract_filename_from_content_disposition(disposition: str) -> Optional[str]:
    """
    Extract filename parameter from Content-Disposition header.
    e.g. attachment; filename="update.apk"
    """
    if not disposition:
        return None
    match = re.search(r'filename\*?=(?:["\']?([^"\';\r\n]+)["\']?|UTF-8\'\'([^"\';\r\n]+))', disposition, re.IGNORECASE)
    if match:
        name = match.group(1) or match.group(2)
        return name.strip() if name else None
    return None


def inspect_download_metadata(
    url: str,
    headers: Dict[str, str],
    initial_bytes: bytes = b""
) -> Dict[str, Any]:
    """
    Statically inspect whether an HTTP response indicates a file download.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    disposition = lower_headers.get("content-disposition", "")
    content_type = lower_headers.get("content-type", "").lower()
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()

    filename = extract_filename_from_content_disposition(disposition)
    if not filename and "/" in path:
        filename = path.split("/")[-1].split("?")[0]

    # Check extension
    extension = os.path.splitext(filename)[1].lower() if filename else ""

    # Check magic bytes
    magic_type = None
    for magic, category in MAGIC_BYTES.items():
        if initial_bytes.startswith(magic):
            magic_type = category
            break

    # Determine file category
    mime_category = detect_file_category_from_mime(content_type)
    file_type = "UNKNOWN"

    if extension == ".apk" or mime_category == "APK" or (magic_type == "ZIP/APK" and extension == ".apk"):
        file_type = "APK"
    elif extension in (".exe", ".msi", ".dll", ".scr") or mime_category == "EXE" or magic_type == "WINDOWS_PE_EXE":
        file_type = "EXE"
    elif extension in (".bat", ".cmd", ".ps1", ".vbs", ".sh"):
        file_type = "SCRIPT"
    elif extension in (".zip", ".rar", ".7z") or mime_category == "ARCHIVE" or magic_type in ("ZIP/APK", "RAR", "7ZIP"):
        file_type = "ARCHIVE"
    elif extension == ".pdf" or mime_category == "PDF" or magic_type == "PDF":
        file_type = "PDF"
    elif mime_category:
        file_type = mime_category

    # Is download explicitly indicated?
    is_attachment = "attachment" in disposition.lower()
    has_binary_mime = content_type in (
        "application/octet-stream",
        "application/vnd.android.package-archive",
        "application/x-msdownload",
        "application/zip",
        "application/x-rar-compressed",
    )
    is_download = is_attachment or has_binary_mime or (file_type in ("APK", "EXE", "SCRIPT", "ARCHIVE") and file_type != "HTML")

    return {
        "download_detected": is_download,
        "is_attachment": is_attachment,
        "filename": filename or "unknown",
        "extension": extension,
        "content_type": content_type,
        "file_type": file_type,
        "magic_signature": magic_type,
        "is_executable": file_type in ("EXE", "SCRIPT"),
        "is_apk": file_type == "APK",
    }


def analyze_downloaded_payload(
    file_bytes: bytes,
    meta: Dict[str, Any],
    source_url: str
) -> Dict[str, Any]:
    """
    Calculates cryptographic hashes, enforces limits, and if an APK is identified,
    hands off the payload to the Phase 07/08 static analysis engine.
    """
    file_size = len(file_bytes)
    oversized = file_size > MAX_DOWNLOAD_SIZE
    processed_bytes = file_bytes[:MAX_DOWNLOAD_SIZE]

    sha256 = hashlib.sha256(processed_bytes).hexdigest()
    sha1 = hashlib.sha1(processed_bytes).hexdigest()
    md5 = hashlib.md5(processed_bytes).hexdigest()

    result: Dict[str, Any] = {
        "download_detected": meta.get("download_detected", True),
        "filename": meta.get("filename", "unknown"),
        "file_type": meta.get("file_type", "UNKNOWN"),
        "extension": meta.get("extension", ""),
        "file_size_bytes": file_size,
        "oversized": oversized,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "is_executable": meta.get("is_executable", False),
        "is_apk": meta.get("is_apk", False),
        "apk_analysis": None,
    }

    # If APK payload detected, route safely to Phase 07/08 static analyzer
    if meta.get("is_apk") and file_size > 0:
        try:
            from app.services.apk_analyzer import analyze_apk_file
            from app.services.apk_permission_analyzer import analyze_apk_permissions
            from app.services.apk_privacy_rule_detector import evaluate_apk_privacy_rules

            with tempfile.NamedTemporaryFile(suffix=".apk", delete=False) as tmp:
                tmp.write(processed_bytes)
                tmp_path = tmp.name

            try:
                # 1. Phase 07 APK Static Security Analysis
                apk_sec = analyze_apk_file(tmp_path)
                perms = apk_sec.get("permissions", [])

                # 2. Phase 08 Permission & Privacy Analysis
                pkg_name = apk_sec.get("package_name") or "downloaded.app"
                perm_eval = analyze_apk_permissions(perms, declared_category=None)
                privacy_eval = evaluate_apk_privacy_rules(
                    package_name=pkg_name,
                    app_name=apk_sec.get("application_label"),
                    permissions=perms,
                    declared_category=None,
                    api_correlations=apk_sec.get("api_correlations", []),
                    target_sdk=apk_sec.get("target_sdk", 33),
                    services_count=apk_sec.get("components", {}).get("services", 0),
                    receivers_count=apk_sec.get("components", {}).get("receivers", 0),
                )

                result["apk_analysis"] = {
                    "package_name": pkg_name,
                    "application_label": apk_sec.get("application_label"),
                    "version_name": apk_sec.get("version_name"),
                    "target_sdk": apk_sec.get("target_sdk"),
                    "rule_risk_score": apk_sec.get("rule_risk_score", 0),
                    "privacy_risk_score": privacy_eval.get("privacy_score", 0),
                    "privacy_risk_level": privacy_eval.get("privacy_risk_level", "very_low"),
                    "permissions_count": len(perms),
                    "sensitive_permissions_count": privacy_eval.get("sensitive_permissions_count", 0),
                    "high_impact_capabilities": privacy_eval.get("high_impact_capabilities", []),
                    "summary": f"Downloaded Android package '{pkg_name}' inspected. Malware risk: {apk_sec.get('rule_risk_score', 0)}/100, Privacy risk: {privacy_eval.get('privacy_score', 0)}/100.",
                    "status": "analyzed",
                }
            finally:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
        except Exception as e:
            result["apk_analysis"] = {
                "status": "analysis_failed",
                "error": f"Static APK analysis error: {str(e)}",
            }

    return result
