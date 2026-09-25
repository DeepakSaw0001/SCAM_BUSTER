"""
ScamBuster ML — URL Preprocessor

Parses a raw URL string into its structural components so that
the feature-engineering stage can work with clean, typed values.
"""

from urllib.parse import urlparse, parse_qs


def parse_url(url: str) -> dict:
    """
    Return a dict of parsed URL components.
    Handles missing schemes gracefully.
    """
    if not isinstance(url, str):
        return _empty_parsed()

    url = url.strip()

    # Add scheme if missing so urlparse works correctly
    if not url.startswith(("http://", "https://", "ftp://")):
        url = "http://" + url

    try:
        parsed = urlparse(url)
    except Exception:
        return _empty_parsed()

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    return {
        "full_url": url,
        "scheme": parsed.scheme,
        "hostname": hostname,
        "path": path,
        "query": query,
        "fragment": parsed.fragment or "",
        "query_params": parse_qs(query),
    }


def _empty_parsed() -> dict:
    return {
        "full_url": "",
        "scheme": "",
        "hostname": "",
        "path": "",
        "query": "",
        "fragment": "",
        "query_params": {},
    }
