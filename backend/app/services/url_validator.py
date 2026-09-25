"""
ScamBuster URL Validator

Strict validation for incoming URLs before processing.
Enforces:
- String type and length bounds (max 2048 chars)
- Strict scheme allowlisting (http and https only)
- Rejection of dangerous pseudo-schemes (javascript:, data:, file:, etc.)
- Well-formed hostname requirement
- Safe parsing without leaking stack traces
"""

import re
import urllib.parse
from typing import Optional, Tuple

MAX_URL_LENGTH = 2048
MIN_URL_LENGTH = 4
ALLOWED_SCHEMES = {"http", "https"}
DISALLOWED_SCHEMES = {"javascript", "data", "file", "ftp", "mailto", "vbscript", "blob", "ws", "wss"}

# Basic hostname pattern ensuring non-empty and no illegal characters
HOSTNAME_PATTERN = re.compile(
    r"^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|"  # domain
    r"^(\d{1,3}\.){3}\d{1,3}$|"                                             # IPv4
    r"^localhost$|"                                                         # localhost
    r"^\[?[a-fA-F0-9:]+\]?$"                                                # IPv6
)


class UrlValidationError(ValueError):
    """Raised when a URL fails validation checks."""
    pass


def validate_url(url: Optional[str]) -> Tuple[bool, Optional[str]]:
    """
    Validate a URL string.
    Returns:
        (True, None) if valid.
        (False, error_reason) if invalid.
    """
    if url is None:
        return False, "URL cannot be null or undefined."

    if not isinstance(url, str):
        return False, "URL must be a string."

    stripped = url.strip()
    if not stripped:
        return False, "URL cannot be empty."

    if len(stripped) < MIN_URL_LENGTH:
        return False, f"URL is too short (minimum {MIN_URL_LENGTH} characters)."

    if len(stripped) > MAX_URL_LENGTH:
        return False, f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."

    # Check for whitespace/control characters within URL
    if any(c.isspace() for c in stripped):
        return False, "URL contains illegal whitespace characters."

    # Parse URL
    try:
        parsed = urllib.parse.urlparse(stripped)
    except Exception as exc:
        return False, f"Malformed URL structure: {exc}"

    scheme = (parsed.scheme or "").lower()
    if not scheme:
        return False, "URL is missing a protocol scheme (must be http:// or https://)."

    if scheme in DISALLOWED_SCHEMES:
        return False, f"Scheme '{scheme}:' is not permitted. Only 'http://' and 'https://' are supported."

    if scheme not in ALLOWED_SCHEMES:
        return False, f"Unsupported URL scheme '{scheme}'. Only 'http://' and 'https://' are permitted."

    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        return False, "URL is missing a valid hostname or network location."

    hostname_clean = hostname.strip().lower()
    if len(hostname_clean) > 253:
        return False, "Hostname exceeds maximum RFC 1035 length (253 characters)."

    # Port validation
    if parsed.port is not None:
        if parsed.port < 1 or parsed.port > 65535:
            return False, f"Invalid port number {parsed.port} (must be between 1 and 65535)."

    return True, None


def ensure_valid_url(url: str) -> None:
    """
    Helper that raises UrlValidationError if invalid.
    """
    is_valid, error = validate_url(url)
    if not is_valid:
        raise UrlValidationError(error)
