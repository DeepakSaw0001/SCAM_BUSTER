"""
ScamBuster URL Normalizer

Normalizes URLs consistently for security analysis while preserving
vital structural signals (such as percent-encoded sequences, embedded credentials,
and exact query casing).

Separates:
- original_url: untouched user input
- normalized_url: canonical form
"""

import re
import urllib.parse
from dataclasses import dataclass
from typing import Dict, List, Optional

IPV4_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


@dataclass
class NormalizedUrlResult:
    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    port: Optional[int]
    path: str
    query: str
    fragment: str
    netloc: str
    is_ip: bool
    has_userinfo: bool
    userinfo: Optional[str]
    query_params: Dict[str, List[str]]


def normalize_url(raw_url: str) -> NormalizedUrlResult:
    """
    Normalize raw URL string for downstream lexical feature extraction and rules.
    Preserves original_url alongside canonical normalized_url.
    """
    original = raw_url.strip()

    # Prepend scheme if missing (for resilience)
    url_to_parse = original
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_to_parse):
        url_to_parse = "http://" + url_to_parse

    parsed = urllib.parse.urlsplit(url_to_parse)

    scheme = (parsed.scheme or "http").lower()

    # Extract userinfo if present (@ symbol before host)
    has_userinfo = "@" in parsed.netloc
    userinfo = None
    host_part = parsed.netloc

    if has_userinfo:
        userinfo_part, _, host_part = parsed.netloc.partition("@")
        userinfo = userinfo_part

    # Handle host and port
    if ":" in host_part and not host_part.startswith("["):
        host_name, _, port_str = host_part.partition(":")
        try:
            port = int(port_str)
        except ValueError:
            port = None
    else:
        host_name = host_part
        port = parsed.port

    hostname = host_name.lower().rstrip(".")
    is_ip = bool(IPV4_PATTERN.match(hostname))

    # Strip default ports from canonical netloc
    include_port = False
    if port is not None:
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            include_port = True

    canonical_netloc = hostname
    if include_port:
        canonical_netloc = f"{hostname}:{port}"
    if has_userinfo and userinfo:
        canonical_netloc = f"{userinfo}@{canonical_netloc}"

    # Path normalization: ensure at least '/'
    path = parsed.path
    if not path:
        path = "/"

    query = parsed.query or ""
    fragment = parsed.fragment or ""

    # Parse query parameters safely
    query_params = urllib.parse.parse_qs(query, keep_blank_values=True)

    # Reconstruct normalized URL
    reconstructed = f"{scheme}://{canonical_netloc}{path}"
    if query:
        reconstructed += f"?{query}"
    if fragment:
        reconstructed += f"#{fragment}"

    return NormalizedUrlResult(
        original_url=original,
        normalized_url=reconstructed,
        scheme=scheme,
        hostname=hostname,
        port=port if include_port else (80 if scheme == "http" else 443),
        path=path,
        query=query,
        fragment=fragment,
        netloc=canonical_netloc,
        is_ip=is_ip,
        has_userinfo=has_userinfo,
        userinfo=userinfo,
        query_params=query_params,
    )
