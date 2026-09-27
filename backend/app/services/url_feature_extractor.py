"""
ScamBuster URL Feature Extractor

Extracts structured, reproducible lexical and structural features from a URL.
Designed for consumption by:
1. Rule-based detection heuristics
2. Initial risk engine
3. Future machine-learning classification pipelines (scikit-learn / joblib)
"""

import math
import re
from collections import Counter
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.services.url_normalizer import NormalizedUrlResult, normalize_url

# Specified trigger keywords for phishing and credential harvesting lures
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "account",
    "update", "password", "bank", "wallet", "payment",
    "confirm", "signin"
]

SPECIAL_CHARACTERS = set("!@#$%^&*()_+={}[]|\\:\";<>,?~`")
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


class UrlFeatures(BaseModel):
    # General Lengths
    url_length: int = Field(..., description="Total length of the URL string")
    hostname_length: int = Field(..., description="Length of the hostname / domain")
    path_length: int = Field(..., description="Length of the path component")
    query_length: int = Field(..., description="Length of the query string")
    fragment_length: int = Field(..., description="Length of the fragment component")

    # Character Counts
    number_of_dots: int = Field(..., description="Number of '.' characters in the URL")
    number_of_hyphens: int = Field(..., description="Number of '-' characters in the URL")
    number_of_digits: int = Field(..., description="Total count of numeric digits")
    number_of_special_characters: int = Field(..., description="Count of special punctuation symbols")
    number_of_slashes: int = Field(..., description="Total count of '/' characters")
    number_of_question_marks: int = Field(..., description="Count of '?' characters")
    number_of_equals: int = Field(..., description="Count of '=' characters")

    # Structural Attributes
    subdomain_count: int = Field(..., description="Number of subdomain labels")
    path_depth: int = Field(..., description="Number of directory segments in the path")
    query_parameter_count: int = Field(..., description="Number of query parameters")
    has_ip_hostname: bool = Field(..., description="True if hostname is a raw IPv4 address")
    has_port: bool = Field(..., description="True if a non-standard port is specified")
    uses_https: bool = Field(..., description="True if protocol scheme is HTTPS")

    # Suspicious Patterns
    suspicious_keyword_count: int = Field(..., description="Number of distinct credential/phishing keywords matched")
    matched_keywords: List[str] = Field(default_factory=list, description="List of matched suspicious keywords")

    # Additional lexical signals for ML compatibility
    has_at_symbol: bool = Field(..., description="True if userinfo '@' symbol is present")
    has_double_slash_redirect: bool = Field(..., description="True if '//' occurs within the path")
    digit_ratio: float = Field(..., description="Ratio of digits to total URL length")
    entropy: float = Field(..., description="Shannon entropy of the URL string")


def _calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy (measure of character randomness)."""
    if not text:
        return 0.0
    length = len(text)
    counts = Counter(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def extract_url_features(url: str, normalized: Optional[NormalizedUrlResult] = None) -> UrlFeatures:
    """
    Extract structured lexical and structural features from a URL.
    Accepts raw URL or pre-normalized URL result.
    """
    norm = normalized or normalize_url(url)
    target = norm.normalized_url

    # Hostname & Subdomains
    hostname = norm.hostname
    # Calculate subdomains: e.g. a.b.example.com -> subdomains: ['a', 'b']
    labels = [label for label in hostname.split(".") if label]
    if norm.is_ip or len(labels) <= 2:
        subdomain_count = 0
    else:
        # Subtract domain and TLD
        subdomain_count = max(len(labels) - 2, 0)

    # Path depth
    path_segments = [seg for seg in norm.path.split("/") if seg]
    path_depth = len(path_segments)

    # Suspicious Keywords Search (in hostname, path, and query)
    lower_target = target.lower()
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in lower_target]

    # Character counts
    num_digits = sum(c.isdigit() for c in target)
    num_special = sum(c in SPECIAL_CHARACTERS for c in target)

    # Non-standard port check
    has_port = False
    if norm.port is not None:
        if (norm.scheme == "http" and norm.port != 80) or (norm.scheme == "https" and norm.port != 443):
            has_port = True

    url_len = len(target)
    digit_ratio = (num_digits / url_len) if url_len > 0 else 0.0

    return UrlFeatures(
        url_length=url_len,
        hostname_length=len(hostname),
        path_length=len(norm.path),
        query_length=len(norm.query),
        fragment_length=len(norm.fragment),
        number_of_dots=target.count("."),
        number_of_hyphens=target.count("-"),
        number_of_digits=num_digits,
        number_of_special_characters=num_special,
        number_of_slashes=target.count("/"),
        number_of_question_marks=target.count("?"),
        number_of_equals=target.count("="),
        subdomain_count=subdomain_count,
        path_depth=path_depth,
        query_parameter_count=len(norm.query_params),
        has_ip_hostname=norm.is_ip,
        has_port=has_port,
        uses_https=norm.scheme == "https",
        suspicious_keyword_count=len(matched_keywords),
        matched_keywords=matched_keywords,
        has_at_symbol="@" in target,
        has_double_slash_redirect="//" in norm.path,
        digit_ratio=round(digit_ratio, 4),
        entropy=round(_calculate_entropy(target), 4),
    )


URL_FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "number_of_dots",
    "number_of_hyphens",
    "number_of_digits",
    "number_of_special_characters",
    "number_of_slashes",
    "number_of_question_marks",
    "number_of_equals",
    "subdomain_count",
    "path_depth",
    "query_parameter_count",
    "has_ip_hostname",
    "has_port",
    "uses_https",
    "suspicious_keyword_count",
    "has_at_symbol",
    "has_double_slash_redirect",
    "digit_ratio",
    "entropy",
]


def extract_feature_dict(url: str, normalized: Optional[NormalizedUrlResult] = None) -> Dict[str, float]:
    """Return dictionary of numerical / boolean features matching URL_FEATURE_NAMES."""
    feats = extract_url_features(url, normalized)
    d = feats.model_dump()
    return {
        name: float(1.0 if d[name] is True else (0.0 if d[name] is False else d[name]))
        for name in URL_FEATURE_NAMES
    }


def extract_feature_vector(url: str, normalized: Optional[NormalizedUrlResult] = None) -> List[float]:
    """Return ordered numerical vector in URL_FEATURE_NAMES order."""
    f_dict = extract_feature_dict(url, normalized)
    return [f_dict[name] for name in URL_FEATURE_NAMES]

