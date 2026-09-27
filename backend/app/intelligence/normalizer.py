"""
ScamBuster — Threat Indicator Normalizer (Phase 11)

Safely sanitizes, validates, and normalizes indicators:
- DOMAIN (lowercase, trailing dots, IDN/punycode, registrable extraction)
- URL (canonical scheme/host, port stripping, path collapse, fragment removal)
- IP (IPv4/IPv6 canonicalization, bogon/private detection via ipaddress)
- FILE_HASH (algorithm validation, hex lowercasing)
- PHONE (reusing existing phone normalizer)
- EMAIL (address validation, domain extraction, privacy sanitization)
"""

import ipaddress
import re
from typing import Any, Dict, Optional, Tuple
import urllib.parse

from app.intelligence.models import IndicatorType, ThreatIndicator
from app.services.phone_normalizer import normalize_phone_number


# Hash length mappings
HASH_LENGTHS = {
    64: "sha256",
    40: "sha1",
    32: "md5",
}

HEX_PATTERN = re.compile(r"^[a-fA-F0-9]+$")
EMAIL_PATTERN = re.compile(r"^([a-zA-Z0-9_.+-]+)@([a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)$")


def normalize_domain(domain_str: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize a domain name:
    - Strips scheme and path if accidentally included
    - Strips whitespace and trailing dot
    - Converts to lowercase
    - Handles IDN / Punycode
    """
    cleaned = domain_str.strip().lower()
    # Strip protocol if passed
    if "://" in cleaned:
        parsed = urllib.parse.urlsplit(cleaned)
        cleaned = parsed.netloc or parsed.path
    if "/" in cleaned:
        cleaned = cleaned.split("/")[0]
    if ":" in cleaned and not cleaned.startswith("["):
        # Strip port if present
        cleaned = cleaned.split(":")[0]

    # Strip trailing dot (DNS root)
    cleaned = cleaned.rstrip(".")

    # Handle IDN / Punycode
    is_idn = False
    try:
        if any(ord(c) > 127 for c in cleaned):
            cleaned = cleaned.encode("idna").decode("ascii")
            is_idn = True
    except Exception:
        pass

    # Extract registrable parts
    parts = cleaned.split(".")
    registrable = ".".join(parts[-2:]) if len(parts) >= 2 else cleaned

    metadata = {
        "is_idn": is_idn,
        "labels_count": len(parts),
        "registrable_domain": registrable,
        "is_subdomain": len(parts) > 2,
    }
    return cleaned, metadata


def normalize_url(url_str: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize a URL:
    - Lowercase scheme and netloc
    - Strip default ports
    - Strip fragment
    - Normalize path slashes
    """
    raw = url_str.strip()
    if " " in raw:
        raise ValueError(f"URL cannot contain spaces: '{url_str}'")
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw):
        raw = "http://" + raw

    parsed = urllib.parse.urlsplit(raw)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    if not netloc or ("." not in netloc and netloc != "localhost" and not netloc.startswith("[")):
        raise ValueError(f"Invalid URL host: '{url_str}'")

    # Strip default ports
    if (scheme == "http" and netloc.endswith(":80")) or (scheme == "https" and netloc.endswith(":443")):
        netloc = netloc.rsplit(":", 1)[0]

    # Normalize path
    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")

    # Sort query parameters for consistent caching
    query = parsed.query
    if query:
        query_pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
        query_pairs.sort()
        query = urllib.parse.urlencode(query_pairs)

    normalized = urllib.parse.urlunsplit((scheme, netloc, path, query, ""))
    hostname = netloc.split(":")[0]

    metadata = {
        "scheme": scheme,
        "hostname": hostname,
        "has_query": bool(query),
        "path_depth": path.count("/"),
    }
    return normalized, metadata


def normalize_ip(ip_str: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize IPv4 or IPv6 address:
    - Returns canonical representation
    - Flags private/loopback/link-local/multicast/reserved ranges
    """
    cleaned = ip_str.strip().strip("[]")
    if ":" in cleaned and cleaned.count(":") == 1:
        # IPv4 with port
        cleaned = cleaned.split(":")[0]

    addr = ipaddress.ip_address(cleaned)
    canonical = str(addr)

    metadata = {
        "version": addr.version,
        "is_private": addr.is_private,
        "is_loopback": addr.is_loopback,
        "is_link_local": addr.is_link_local,
        "is_multicast": addr.is_multicast,
        "is_reserved": addr.is_reserved,
        "is_bogon": addr.is_private or addr.is_loopback or addr.is_reserved,
    }
    return canonical, metadata


def normalize_file_hash(hash_str: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize cryptographic file hash:
    - Lowercase hex string
    - Detects algorithm (sha256, sha1, md5)
    """
    cleaned = hash_str.strip().lower()
    if not HEX_PATTERN.match(cleaned):
        raise ValueError(f"Invalid hexadecimal hash string: '{hash_str}'")

    algo = HASH_LENGTHS.get(len(cleaned), "unknown")
    if algo == "unknown":
        raise ValueError(f"Unrecognized hash length ({len(cleaned)} chars). Supported: SHA-256, SHA-1, MD5.")

    metadata = {
        "algorithm": algo,
        "bit_length": len(cleaned) * 4,
    }
    return cleaned, metadata


def normalize_email(email_str: str) -> Tuple[str, Dict[str, Any]]:
    """
    Normalize email address:
    - Lowercase
    - Extracts domain and user portion
    - Creates privacy-masked string for logs/lookups
    """
    cleaned = email_str.strip().lower()
    match = EMAIL_PATTERN.match(cleaned)
    if not match:
        raise ValueError(f"Invalid email address syntax: '{email_str}'")

    user_part, domain_part = match.groups()
    norm_domain, dom_meta = normalize_domain(domain_part)
    normalized = f"{user_part}@{norm_domain}"

    # Mask user part for privacy
    if len(user_part) <= 2:
        masked_user = user_part[0] + "*"
    else:
        masked_user = user_part[0] + "***" + user_part[-1]
    masked_email = f"{masked_user}@{norm_domain}"

    metadata = {
        "domain": norm_domain,
        "masked_email": masked_email,
        "domain_metadata": dom_meta,
    }
    return normalized, metadata


def normalize_indicator(
    type_: IndicatorType,
    value: str,
    source: str = "scan_target",
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> ThreatIndicator:
    """
    Central dispatch for normalizing any threat indicator type safely.
    Raises ValueError on invalid input syntax.
    """
    val = value.strip()
    meta = dict(extra_metadata or {})

    if type_ == IndicatorType.DOMAIN:
        norm_val, d_meta = normalize_domain(val)
        meta.update(d_meta)
    elif type_ == IndicatorType.URL:
        norm_val, u_meta = normalize_url(val)
        meta.update(u_meta)
    elif type_ == IndicatorType.IP:
        norm_val, ip_meta = normalize_ip(val)
        meta.update(ip_meta)
    elif type_ == IndicatorType.FILE_HASH:
        norm_val, h_meta = normalize_file_hash(val)
        meta.update(h_meta)
    elif type_ == IndicatorType.PHONE:
        norm_phone = normalize_phone_number(val)
        if not norm_phone.is_valid and not norm_phone.is_possible:
            norm_val = val
            meta["is_valid_phone"] = False
        else:
            norm_val = norm_phone.e164 or val
            meta["region_code"] = norm_phone.region_code
            meta["carrier"] = norm_phone.carrier_name
            meta["number_type"] = norm_phone.number_type_name
            meta["is_valid_phone"] = norm_phone.is_valid
            meta["masked"] = norm_phone.masked
    elif type_ == IndicatorType.EMAIL:
        norm_val, e_meta = normalize_email(val)
        meta.update(e_meta)
    else:
        norm_val = val.lower()

    return ThreatIndicator(
        type=type_,
        value=val,
        normalized_value=norm_val,
        source=source,
        metadata=meta,
    )


# Convenience safe helper functions returning normalized string or None

def normalize_domain_indicator(domain_str: str) -> Optional[str]:
    """Safely normalize a domain string, returning None if invalid."""
    if not domain_str or not str(domain_str).strip() or ".." in str(domain_str):
        return None
    try:
        norm, _ = normalize_domain(domain_str)
        return norm if norm and "." in norm else (norm if norm else None)
    except Exception:
        return None


def normalize_url_indicator(url_str: str) -> Optional[str]:
    """Safely normalize a URL indicator, returning None if invalid."""
    if not url_str or not str(url_str).strip():
        return None
    try:
        norm, _ = normalize_url(url_str)
        return norm
    except Exception:
        return None


def normalize_ip_indicator(ip_str: str) -> Optional[str]:
    """Safely normalize an IP indicator, returning None if invalid."""
    if not ip_str or not str(ip_str).strip():
        return None
    try:
        norm, _ = normalize_ip(ip_str)
        return norm
    except Exception:
        return None


def normalize_file_hash_indicator(hash_str: str) -> Optional[str]:
    """Safely normalize a file hash indicator, returning None if invalid."""
    if not hash_str or not str(hash_str).strip():
        return None
    try:
        norm, _ = normalize_file_hash(hash_str)
        return norm
    except Exception:
        return None


def normalize_phone_indicator(phone_str: str, default_region: Optional[str] = None) -> Optional[str]:
    """Safely normalize a phone indicator using the phone normalizer, returning None if invalid."""
    if not phone_str or not str(phone_str).strip():
        return None
    try:
        res = normalize_phone_number(phone_str, default_region=default_region)
        return res.e164 if res.is_valid or res.is_possible else None
    except Exception:
        return None


def normalize_email_indicator(email_str: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Safely normalize an email indicator.
    Returns (normalized_email, domain, masked_email) or (None, None, None) on failure.
    """
    if not email_str or not str(email_str).strip():
        return None, None, None
    try:
        norm, meta = normalize_email(email_str)
        return norm, meta.get("domain"), meta.get("masked_email")
    except Exception:
        return None, None, None


def detect_indicator_type(value: str) -> IndicatorType:
    """Heuristically deduce indicator type from input string."""
    val = value.strip()
    if val.startswith("http://") or val.startswith("https://"):
        return IndicatorType.URL
    if "@" in val and not val.startswith("@"):
        return IndicatorType.EMAIL
    if HEX_PATTERN.match(val) and len(val) in (32, 40, 64):
        return IndicatorType.FILE_HASH
    try:
        ipaddress.ip_address(val.strip("[]"))
        return IndicatorType.IP
    except ValueError:
        pass
    if re.match(r"^(\+?\d{1,4}[-.\s]?)?(\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{4}$", val) and len(re.sub(r"\D", "", val)) >= 7:
        return IndicatorType.PHONE
    if "." in val and "/" in val:
        return IndicatorType.URL
    return IndicatorType.DOMAIN
