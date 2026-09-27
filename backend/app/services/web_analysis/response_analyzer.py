"""
Response & Security Headers Analyzer

Evaluates HTTP response status codes, transport security (HTTPS/TLS),
and presence of defensive browser security headers (CSP, HSTS, X-Content-Type-Options).

Follows project principle:
Absence of security headers or use of HTTP indicates transport hardening gaps,
NOT definitive evidence of malware.
"""

from typing import Any, Dict, List, Optional
import urllib.parse


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Check for essential defensive security headers and return hardening status.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}

    csp = lower_headers.get("content-security-policy")
    hsts = lower_headers.get("strict-transport-security")
    x_content_type = lower_headers.get("x-content-type-options")
    x_frame = lower_headers.get("x-frame-options")
    referrer_policy = lower_headers.get("referrer-policy")
    permissions_policy = lower_headers.get("permissions-policy")

    missing: List[str] = []
    if not csp:
        missing.append("Content-Security-Policy")
    if not hsts:
        missing.append("Strict-Transport-Security")
    if not x_content_type:
        missing.append("X-Content-Type-Options")
    if not x_frame and not (csp and "frame-ancestors" in csp.lower()):
        missing.append("X-Frame-Options / frame-ancestors")

    hardening_score = 100 - (len(missing) * 20)
    hardening_score = max(hardening_score, 0)

    return {
        "hardening_score": hardening_score,
        "present_headers": {
            "content_security_policy": bool(csp),
            "strict_transport_security": bool(hsts),
            "x_content_type_options": bool(x_content_type),
            "x_frame_options": bool(x_frame),
            "referrer_policy": bool(referrer_policy),
            "permissions_policy": bool(permissions_policy),
        },
        "details": {
            "hsts_raw": hsts[:128] if hsts else None,
            "x_content_type_options_nosniff": (x_content_type or "").strip().lower() == "nosniff",
            "x_frame_options_raw": x_frame,
            "referrer_policy_raw": referrer_policy,
        },
        "missing_headers": missing,
        "observation": (
            "Well-hardened web application headers observed."
            if not missing else
            f"Defensive header hardening gaps observed: missing {', '.join(missing)}."
        )
    }


def analyze_http_response(
    status_code: int,
    headers: Dict[str, str],
    final_url: str,
    tls_info: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Synthesize complete HTTP transport, response, and TLS profile.
    """
    lower_headers = {k.lower(): v for k, v in headers.items()}
    parsed = urllib.parse.urlparse(final_url)
    is_https = parsed.scheme.lower() == "https"

    content_type = lower_headers.get("content-type", "unknown")
    content_length_str = lower_headers.get("content-length")
    content_length = int(content_length_str) if content_length_str and content_length_str.isdigit() else None
    server = lower_headers.get("server", "hidden")

    # Sanitize server header
    if len(server) > 64:
        server = server[:64] + "..."

    sec_headers = analyze_security_headers(headers)

    tls_summary = {
        "is_https": is_https,
        "certificate_valid": tls_info.get("valid", True) if (tls_info and is_https) else is_https,
        "certificate_error": tls_info.get("error") if tls_info else None,
        "tls_version": tls_info.get("version") if tls_info else ("TLSv1.3/TLSv1.2" if is_https else "None"),
        "transport_explanation": (
            "Encrypted HTTPS channel established. Note: Transport encryption protects in-flight data, but does not verify website benevolence."
            if is_https else
            "Unencrypted cleartext HTTP channel. Vulnerable to network eavesdropping and adversary-in-the-middle modification."
        ),
    }

    return {
        "status_code": status_code,
        "content_type": content_type,
        "content_length": content_length,
        "server": server,
        "is_https": is_https,
        "tls": tls_summary,
        "security_headers": sec_headers,
    }
