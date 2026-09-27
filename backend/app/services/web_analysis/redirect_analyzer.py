"""
Redirect Chain & Domain Analysis

Safely analyzes redirect chains, detects redirect loops, cross-domain navigation,
domain hopping, URL shorteners, HTML meta-refreshes, and static JavaScript redirects.
"""

import re
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple

# Known URL shorteners
SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "is.gd", "t.co", "cutt.ly", "rb.gy", "ow.ly",
    "goo.gl", "buff.ly", "adf.ly", "shorturl.at", "tiny.cc", "lnkd.in",
    "rebrand.ly", "qr.ae", "trib.al", "cli.re", "bl.ink"
}

# Regex to detect meta refresh tags
META_REFRESH_PATTERN = re.compile(
    r'<meta\s+[^>]*http-equiv=["\']?refresh["\']?[^>]*content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)["\']?',
    re.IGNORECASE
)

# Regex to detect static JavaScript redirection calls without running any JS engine
JS_REDIRECT_PATTERNS = [
    re.compile(r'(?:window\.)?location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
    re.compile(r'(?:window\.)?location\.(?:replace|assign)\s*\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE),
    re.compile(r'top\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']', re.IGNORECASE),
]


def extract_registrable_domain(hostname: str) -> str:
    """
    Extract approximate base/registrable domain from hostname.
    Handles common two-part ccTLDs (.co.uk, .com.au, .co.in, etc.)
    """
    if not hostname:
        return ""
    host = hostname.strip().lower().rstrip(".")
    parts = host.split(".")
    if len(parts) <= 2:
        return host

    # Common multi-part suffixes
    second_level_tlds = {"co", "com", "net", "org", "gov", "edu", "ac"}
    if len(parts) >= 3 and parts[-2] in second_level_tlds and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    
    return ".".join(parts[-2:])


class RedirectTracker:
    """
    Tracks and analyzes an HTTP/HTTPS redirect progression step-by-step.
    """

    def __init__(self, initial_url: str):
        self.initial_url = initial_url
        self.initial_parsed = urllib.parse.urlparse(initial_url)
        self.initial_domain = (self.initial_parsed.hostname or "").lower()
        self.initial_reg_domain = extract_registrable_domain(self.initial_domain)

        self.hops: List[Dict[str, Any]] = []
        self.visited_urls: Set[str] = {initial_url}
        self.visited_domains: List[str] = [self.initial_domain]
        self.distinct_reg_domains: Set[str] = {self.initial_reg_domain}

        self.loop_detected = False
        self.limit_reached = False
        self.shortener_detected = self.initial_domain in SHORTENER_DOMAINS
        self.meta_refresh_detected = False
        self.js_redirect_detected = False

    def add_hop(
        self,
        from_url: str,
        to_url: str,
        status_code: int,
        redirect_type: str = "HTTP"
    ) -> Tuple[bool, Optional[str]]:
        """
        Record a redirection step. Returns (continue_following, stop_reason).
        """
        # Resolve relative target URLs
        resolved_to_url = urllib.parse.urljoin(from_url, to_url)
        parsed_target = urllib.parse.urlparse(resolved_to_url)
        target_domain = (parsed_target.hostname or "").lower()
        target_reg_domain = extract_registrable_domain(target_domain)

        if target_domain in SHORTENER_DOMAINS:
            self.shortener_detected = True

        # Check for loop
        if resolved_to_url in self.visited_urls:
            self.loop_detected = True
            hop_info = {
                "step": len(self.hops) + 1,
                "from_url": self._sanitize_url(from_url),
                "to_url": self._sanitize_url(resolved_to_url),
                "target_domain": target_domain,
                "status_code": status_code,
                "redirect_type": redirect_type,
                "is_cross_domain": target_reg_domain != self.initial_reg_domain,
            }
            self.hops.append(hop_info)
            return False, f"Redirect loop detected targeting previously visited URL: {self._sanitize_url(resolved_to_url)}"

        # Check cross-domain
        from_parsed = urllib.parse.urlparse(from_url)
        from_reg_domain = extract_registrable_domain((from_parsed.hostname or "").lower())
        is_cross_domain = target_reg_domain != from_reg_domain

        hop_info = {
            "step": len(self.hops) + 1,
            "from_url": self._sanitize_url(from_url),
            "to_url": self._sanitize_url(resolved_to_url),
            "target_domain": target_domain,
            "status_code": status_code,
            "redirect_type": redirect_type,
            "is_cross_domain": is_cross_domain,
        }
        self.hops.append(hop_info)
        self.visited_urls.add(resolved_to_url)
        self.visited_domains.append(target_domain)
        if target_reg_domain:
            self.distinct_reg_domains.add(target_reg_domain)

        return True, None

    def analyze_html_redirects(self, html_content: str, current_url: str) -> Optional[Dict[str, Any]]:
        """
        Statically inspects HTML for meta refresh or JavaScript redirect signals.
        """
        if not html_content or not isinstance(html_content, str):
            return None

        # 1. Meta refresh check
        meta_match = META_REFRESH_PATTERN.search(html_content[:4096])
        if meta_match:
            self.meta_refresh_detected = True
            target_candidate = meta_match.group(1).strip()
            resolved = urllib.parse.urljoin(current_url, target_candidate)
            return {
                "type": "META_REFRESH",
                "target_url": resolved,
                "raw_target": target_candidate,
            }

        # 2. JavaScript redirect check in first 16KB of HTML/script
        for pattern in JS_REDIRECT_PATTERNS:
            js_match = pattern.search(html_content[:16384])
            if js_match:
                self.js_redirect_detected = True
                target_candidate = js_match.group(1).strip()
                # Skip trivial anchor hashes or javascript: pseudoprotocol
                if target_candidate.startswith("#") or target_candidate.startswith("javascript:"):
                    continue
                resolved = urllib.parse.urljoin(current_url, target_candidate)
                return {
                    "type": "JAVASCRIPT_LOCATION",
                    "target_url": resolved,
                    "raw_target": target_candidate,
                }

        return None

    def get_summary(self, final_url: str) -> Dict[str, Any]:
        """
        Produce a consolidated redirect summary report.
        """
        parsed_final = urllib.parse.urlparse(final_url)
        final_domain = (parsed_final.hostname or "").lower()
        final_reg_domain = extract_registrable_domain(final_domain)

        cross_domain_hops = sum(1 for h in self.hops if h.get("is_cross_domain"))
        domain_hopping = len(self.distinct_reg_domains) >= 3

        return {
            "initial_url": self._sanitize_url(self.initial_url),
            "final_url": self._sanitize_url(final_url),
            "initial_domain": self.initial_domain,
            "final_domain": final_domain,
            "redirect_count": len(self.hops),
            "cross_domain_count": cross_domain_hops,
            "has_cross_domain": cross_domain_hops > 0,
            "domain_hopping": domain_hopping,
            "distinct_domain_count": len(self.distinct_reg_domains),
            "loop_detected": self.loop_detected,
            "limit_reached": self.limit_reached,
            "shortener_detected": self.shortener_detected,
            "meta_refresh_detected": self.meta_refresh_detected,
            "js_redirect_detected": self.js_redirect_detected,
            "chain": self.hops,
        }

    @staticmethod
    def _sanitize_url(raw_url: str) -> str:
        """
        Redact sensitive tokens / credentials from query strings while keeping path intact.
        """
        if not raw_url:
            return ""
        try:
            parsed = urllib.parse.urlparse(raw_url)
            if not parsed.query:
                return raw_url

            query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
            redacted_params = []
            sensitive_keys = {"token", "auth", "api_key", "apikey", "secret", "password", "session", "pass"}
            for k, v in query_params:
                if any(s in k.lower() for s in sensitive_keys):
                    redacted_params.append((k, "[REDACTED]"))
                else:
                    redacted_params.append((k, v))

            new_query = urllib.parse.urlencode(redacted_params)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        except Exception:
            return raw_url
