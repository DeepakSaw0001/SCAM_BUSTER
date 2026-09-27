"""
ScamBuster — Email Preprocessor & Static Link/HTML Analyzer (Phase 05)

Provides:
- Safe HTML text and structure extraction (zero remote fetches, zero JS execution).
- Link extraction and Displayed Text vs. Actual Destination (Anchor Mismatch) detection.
- Static domain comparison (Sender Domain vs. Reply-To Domain).
- Tracking and hidden element counts.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from app.services.email_parser import ParsedEmail


# Regex for URL extraction in plain text
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}\.|[a-z0-9.\-]+[.][a-z]{2,63}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.IGNORECASE,
)

# Anchor tag parser
ANCHOR_REGEX = re.compile(r"""<a\s+(?:[^>]*?\s+)?href=["']([^"']+)["'][^>]*>(.*?)</a>""", re.DOTALL | re.IGNORECASE)
FORM_REGEX = re.compile(r"""<form[^>]*>""", re.IGNORECASE)
HIDDEN_INPUT_REGEX = re.compile(r"""<input[^>]+type=["']hidden["'][^>]*>""", re.IGNORECASE)
EXTERNAL_IMAGE_REGEX = re.compile(r"""<img[^>]+src=["'](https?://[^"']+)["'][^>]*>""", re.IGNORECASE)


@dataclass
class ExtractedEmailLink:
    displayed_text: str
    actual_url: str
    hostname: str
    scheme: str
    is_anchor_mismatch: bool
    mismatch_details: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "displayed_text": self.displayed_text,
            "actual_url": self.actual_url,
            "hostname": self.hostname,
            "scheme": self.scheme,
            "is_anchor_mismatch": self.is_anchor_mismatch,
            "mismatch_details": self.mismatch_details,
        }


@dataclass
class PreprocessedEmailData:
    parsed_email: ParsedEmail
    extracted_urls: List[str]
    unique_domains: List[str]
    extracted_links: List[ExtractedEmailLink]
    anchor_mismatches: List[ExtractedEmailLink]

    has_sender_replyto_mismatch: bool
    domain_mismatch_reason: Optional[str]

    html_link_count: int
    html_form_count: int
    html_hidden_element_count: int
    html_external_resource_count: int

    clean_body_text: str
    clean_subject_text: str


def _clean_text_snippet(s: str) -> str:
    """Strip tags and extra spaces from link text."""
    clean = re.sub(r"<[^>]+>", " ", s)
    return re.sub(r"\s+", " ", clean).strip()


def _extract_hostname(url_str: str) -> str:
    """Safely extract lowercase hostname from URL string."""
    try:
        if not url_str.startswith(("http://", "https://")):
            url_str = "http://" + url_str
        parsed = urlparse(url_str)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def check_anchor_mismatch(displayed_text: str, actual_href: str) -> Tuple[bool, Optional[str]]:
    """
    Detect if the displayed anchor text misleadingly claims one domain / service
    while the actual href directs the victim to another destination.

    Example:
      Displayed: "https://paypal.com/verify-account"
      Actual:    "http://security-update-center.xyz/login"
    """
    clean_disp = _clean_text_snippet(displayed_text)
    actual_host = _extract_hostname(actual_href)

    if not actual_host or not clean_disp:
        return False, None

    # Check if the displayed text contains a domain or URL
    disp_host = _extract_hostname(clean_disp)
    if disp_host and "." in disp_host:
        # Both appear to be hostnames/URLs
        if disp_host != actual_host:
            # Check if one is a subdomain of the other
            if not actual_host.endswith("." + disp_host) and not disp_host.endswith("." + actual_host):
                return True, f"Link text visually displays '{disp_host}' but redirects to '{actual_host}'"

    # Check brand keyword in displayed text vs untrusted actual host
    common_targets = [
        "paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase",
        "wellsfargo", "bankofamerica", "citi", "irs", "usps", "fedex", "dhl"
    ]
    for brand in common_targets:
        if brand in clean_disp.lower() and brand not in actual_host:
            # If text explicitly says e.g. "PayPal Security" or "Chase Login", but host doesn't contain the brand
            if any(term in clean_disp.lower() for term in ["login", "verify", "account", "security", "update", "sign in"]):
                return True, f"Displayed text cites '{brand}' security/login, but actual URL hostname is '{actual_host}'"

    return False, None


def preprocess_email(email_obj: ParsedEmail) -> PreprocessedEmailData:
    """
    Execute static email preprocessing, link parsing, anchor mismatch analysis,
    and sender domain consistency verification.
    """
    all_urls: List[str] = []
    extracted_links: List[ExtractedEmailLink] = []
    anchor_mismatches: List[ExtractedEmailLink] = []

    # 1. Parse HTML links if HTML body is present
    html_link_count = 0
    html_form_count = 0
    html_hidden_count = 0
    html_ext_res_count = 0

    if email_obj.body_html:
        # Detect HTML forms and inputs
        html_form_count = len(FORM_REGEX.findall(email_obj.body_html))
        html_hidden_count = len(HIDDEN_INPUT_REGEX.findall(email_obj.body_html))
        html_ext_res_count = len(EXTERNAL_IMAGE_REGEX.findall(email_obj.body_html))

        # Extract anchor tags
        for match in ANCHOR_REGEX.finditer(email_obj.body_html):
            href = match.group(1).strip()
            anchor_text = match.group(2).strip()
            html_link_count += 1

            if href.startswith(("http://", "https://", "www.")):
                all_urls.append(href)
                host = _extract_hostname(href)
                scheme = "https" if href.startswith("https") else "http"
                is_mismatch, reason = check_anchor_mismatch(anchor_text, href)

                link_item = ExtractedEmailLink(
                    displayed_text=_clean_text_snippet(anchor_text) or href,
                    actual_url=href,
                    hostname=host,
                    scheme=scheme,
                    is_anchor_mismatch=is_mismatch,
                    mismatch_details=reason,
                )
                extracted_links.append(link_item)
                if is_mismatch:
                    anchor_mismatches.append(link_item)

    # 2. Extract plain text URLs from body_text
    plain_url_matches = URL_REGEX.findall(email_obj.body_text)
    for m in plain_url_matches:
        raw_url = m[0].strip()
        if raw_url not in all_urls:
            all_urls.append(raw_url)
            host = _extract_hostname(raw_url)
            scheme = "https" if raw_url.startswith("https") else "http"
            extracted_links.append(
                ExtractedEmailLink(
                    displayed_text=raw_url,
                    actual_url=raw_url,
                    hostname=host,
                    scheme=scheme,
                    is_anchor_mismatch=False,
                    mismatch_details=None,
                )
            )

    # Deduplicate URLs and collect unique domains
    unique_domains = list({
        _extract_hostname(u) for u in all_urls if _extract_hostname(u)
    })

    # 3. Analyze Sender vs Reply-To domains
    has_mismatch = False
    mismatch_reason = None

    if email_obj.reply_to_domain and email_obj.sender_domain:
        s_dom = email_obj.sender_domain.lower()
        r_dom = email_obj.reply_to_domain.lower()

        # If domains differ and neither is a direct parent/subdomain of each other
        if s_dom != r_dom and not s_dom.endswith("." + r_dom) and not r_dom.endswith("." + s_dom):
            has_mismatch = True
            mismatch_reason = (
                f"From address domain '{s_dom}' diverges from Reply-To address domain '{r_dom}'"
            )

    return PreprocessedEmailData(
        parsed_email=email_obj,
        extracted_urls=all_urls,
        unique_domains=unique_domains,
        extracted_links=extracted_links,
        anchor_mismatches=anchor_mismatches,
        has_sender_replyto_mismatch=has_mismatch,
        domain_mismatch_reason=mismatch_reason,
        html_link_count=html_link_count,
        html_form_count=html_form_count,
        html_hidden_element_count=html_hidden_count,
        html_external_resource_count=html_ext_res_count,
        clean_body_text=email_obj.body_text,
        clean_subject_text=email_obj.subject,
    )
