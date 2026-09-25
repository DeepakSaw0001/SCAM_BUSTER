"""
ScamBuster ML — URL Feature Engineering

Extracts numerical / boolean features from a URL string.
These features are used as the input vector for the URL classifier.

IMPORTANT: These features alone do NOT prove a URL is malicious.
They are statistical signals used for ML classification.
"""

import math
import re
from collections import Counter
from urllib.parse import urlparse, parse_qs

# Keywords commonly seen in phishing URLs
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "confirm", "password", "suspend", "alert", "pay",
    "wallet", "free", "prize", "winner", "click", "urgent",
    "ebay", "paypal", "apple", "microsoft", "google",
]

# Ordered feature names — the classifier expects this exact order.
FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "num_dots",
    "num_subdomains",
    "num_digits",
    "num_special_chars",
    "has_at_symbol",
    "has_ip_address",
    "is_https",
    "num_hyphens",
    "num_query_params",
    "path_depth",
    "has_double_slash_redirect",
    "num_suspicious_keywords",
    "digit_ratio",
    "entropy",
]


def extract_url_features(url: str) -> dict:
    """
    Given a raw URL string, return a dict of engineered features.
    Keys match FEATURE_NAMES.
    """
    if not isinstance(url, str) or not url.strip():
        return {name: 0 for name in FEATURE_NAMES}

    url = url.strip()

    # Ensure scheme for urlparse
    url_for_parse = url if url.startswith(("http://", "https://")) else "http://" + url

    try:
        parsed = urlparse(url_for_parse)
    except Exception:
        return {name: 0 for name in FEATURE_NAMES}

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""
    full = url_for_parse

    return {
        "url_length": len(full),
        "hostname_length": len(hostname),
        "path_length": len(path),
        "num_dots": full.count("."),
        "num_subdomains": max(len(hostname.split(".")) - 2, 0),
        "num_digits": sum(c.isdigit() for c in full),
        "num_special_chars": sum(c in "!@#$%^&*()_+={}[]|\\:\";<>,?~`" for c in full),
        "has_at_symbol": int("@" in full),
        "has_ip_address": int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", hostname))),
        "is_https": int(parsed.scheme == "https"),
        "num_hyphens": full.count("-"),
        "num_query_params": len(parse_qs(query)),
        "path_depth": len([seg for seg in path.split("/") if seg]),
        "has_double_slash_redirect": int("//" in path),
        "num_suspicious_keywords": sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in full.lower()),
        "digit_ratio": _digit_ratio(full),
        "entropy": _shannon_entropy(full),
    }


def extract_features_vector(url: str) -> list[float]:
    """Return the feature values as a list in FEATURE_NAMES order."""
    feats = extract_url_features(url)
    return [float(feats[name]) for name in FEATURE_NAMES]


# ── helpers ──────────────────────────────────────────────────────────────
def _digit_ratio(s: str) -> float:
    if not s:
        return 0.0
    return sum(c.isdigit() for c in s) / len(s)


def _shannon_entropy(s: str) -> float:
    """Shannon entropy of the character distribution in the string."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )
