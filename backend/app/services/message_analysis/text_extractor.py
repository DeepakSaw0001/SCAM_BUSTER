"""
ScamBuster — Safe HTML Email & Content Extractor (Phase 10)

Extracts content from HTML messages safely:
- Strictly zero JavaScript execution
- Zero remote resource rendering or network requests
- Zero automated form submissions or link clicks

Extracts:
- Visible sanitized text
- All hyperlinks with visible anchor text vs actual destination (Anchor Mismatch detection)
- Forms and input types (especially password/hidden inputs)
- Iframe references
- Embedded image sources
- Hidden styling tricks (display:none, font-size:0, 1x1 tracking pixels)
"""

from dataclasses import dataclass, field
from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse


@dataclass
class ExtractedHTMLLink:
    displayed_text: str
    href: str
    actual_hostname: str
    displayed_hostname: Optional[str]
    is_anchor_mismatch: bool
    mismatch_description: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "displayed_text": self.displayed_text,
            "href": self.href,
            "actual_hostname": self.actual_hostname,
            "displayed_hostname": self.displayed_hostname,
            "is_anchor_mismatch": self.is_anchor_mismatch,
            "mismatch_description": self.mismatch_description,
        }


@dataclass
class ExtractedHTMLForm:
    action: str
    method: str
    has_password_field: bool
    has_hidden_fields: bool
    input_names: List[str]


@dataclass
class SafeHTMLExtractionResult:
    visible_text: str
    extracted_links: List[ExtractedHTMLLink]
    anchor_mismatches: List[ExtractedHTMLLink]
    forms: List[ExtractedHTMLForm]
    iframes: List[str]
    image_sources: List[str]
    hidden_element_count: int
    has_password_form: bool
    raw_html_size: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_links": len(self.extracted_links),
            "anchor_mismatches_count": len(self.anchor_mismatches),
            "forms_count": len(self.forms),
            "iframes_count": len(self.iframes),
            "images_count": len(self.image_sources),
            "hidden_element_count": self.hidden_element_count,
            "has_password_form": self.has_password_form,
            "raw_html_size": self.raw_html_size,
        }


def _extract_hostname(url_str: str) -> str:
    """Safely extract lowercase hostname from URL string."""
    try:
        clean = url_str.strip()
        if not clean.startswith(("http://", "https://")):
            clean = "http://" + clean
        return (urlparse(clean).hostname or "").lower()
    except Exception:
        return ""


def evaluate_anchor_mismatch(displayed_text: str, href: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """
    Detect if displayed anchor text misleadingly claims one URL/domain
    while href navigates to an entirely different destination.

    Example:
      Displayed: "https://chase.com/login"
      Href:      "https://attacker-portal.net/auth"
    """
    clean_disp = displayed_text.strip()
    actual_host = _extract_hostname(href)

    if not actual_host or not clean_disp:
        return False, None, None

    # Check if displayed text looks like a URL or domain
    disp_host = _extract_hostname(clean_disp)
    if disp_host and "." in disp_host and not any(c in clean_disp for c in [" ", "\t", "\n"]):
        if disp_host != actual_host:
            # Check if one is a valid subdomain of the other
            if not actual_host.endswith("." + disp_host) and not disp_host.endswith("." + actual_host):
                desc = (
                    f"Link text and destination differ: anchor text displays '{disp_host}' "
                    f"but links to destination '{actual_host}'."
                )
                return True, disp_host, desc

    # Brand claim in link text vs unrelated host
    high_value_brands = ["paypal", "apple", "google", "microsoft", "amazon", "netflix", "chase", "wellsfargo", "bankofamerica"]
    for b in high_value_brands:
        if b in clean_disp.lower() and b not in actual_host:
            if any(term in clean_disp.lower() for term in ["login", "sign in", "verify", "secure", "update", "account"]):
                desc = (
                    f"Link text claims {b.capitalize()} security/login action ('{clean_disp[:40]}'), "
                    f"but destination hostname is '{actual_host}'."
                )
                return True, None, desc

    return False, None, None


class _SafeEmailHTMLParser(HTMLParser):
    """
    Fast standard library HTML parser designed for static email inspection.
    Ignores scripts/styles, records text, captures links, forms, iframes, images.
    """

    def __init__(self):
        super().__init__()
        self.text_parts: List[str] = []
        self.in_ignored_tag = False
        self.ignored_tags = {"script", "style", "svg", "noscript"}

        # Link tracking
        self.current_a_href: Optional[str] = None
        self.current_a_text: List[str] = []
        self.extracted_links: List[ExtractedHTMLLink] = []

        # Form tracking
        self.current_form: Optional[ExtractedHTMLForm] = None
        self.forms: List[ExtractedHTMLForm] = []

        # Other tags
        self.iframes: List[str] = []
        self.image_sources: List[str] = []
        self.hidden_element_count = 0

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        if tag_lower in self.ignored_tags:
            self.in_ignored_tag = True
            return

        # Check hidden styling
        style = attr_dict.get("style", "").lower()
        if "display:none" in style or "display: none" in style or "visibility:hidden" in style or "font-size:0" in style:
            self.hidden_element_count += 1

        if tag_lower == "a":
            href = attr_dict.get("href", "").strip()
            self.current_a_href = href
            self.current_a_text = []

        elif tag_lower == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            self.current_form = ExtractedHTMLForm(
                action=action,
                method=method,
                has_password_field=False,
                has_hidden_fields=False,
                input_names=[],
            )

        elif tag_lower == "input":
            itype = attr_dict.get("type", "text").lower()
            iname = attr_dict.get("name", "")
            if itype == "password" and self.current_form:
                self.current_form.has_password_field = True
            elif itype == "hidden":
                self.hidden_element_count += 1
                if self.current_form:
                    self.current_form.has_hidden_fields = True
            if self.current_form and iname:
                self.current_form.input_names.append(iname)

        elif tag_lower == "iframe":
            src = attr_dict.get("src", "").strip()
            if src:
                self.iframes.append(src)

        elif tag_lower == "img":
            src = attr_dict.get("src", "").strip()
            if src:
                self.image_sources.append(src)
            # Check 1x1 tracking pixel
            w = attr_dict.get("width", "")
            h = attr_dict.get("height", "")
            if w in {"0", "1"} and h in {"0", "1"}:
                self.hidden_element_count += 1

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower in self.ignored_tags:
            self.in_ignored_tag = False
            return

        if tag_lower == "a" and self.current_a_href is not None:
            href = self.current_a_href
            disp = " ".join(self.current_a_text).strip()
            if href.startswith(("http://", "https://", "www.")):
                actual_host = _extract_hostname(href)
                is_mismatch, disp_host, reason = evaluate_anchor_mismatch(disp, href)
                self.extracted_links.append(
                    ExtractedHTMLLink(
                        displayed_text=disp or href,
                        href=href,
                        actual_hostname=actual_host,
                        displayed_hostname=disp_host,
                        is_anchor_mismatch=is_mismatch,
                        mismatch_description=reason,
                    )
                )
            self.current_a_href = None
            self.current_a_text = []

        elif tag_lower == "form" and self.current_form is not None:
            self.forms.append(self.current_form)
            self.current_form = None

    def handle_data(self, data: str):
        if self.in_ignored_tag:
            return
        cleaned = data.strip()
        if cleaned:
            self.text_parts.append(cleaned)
            if self.current_a_href is not None:
                self.current_a_text.append(cleaned)


def extract_html_email_content(html_content: str) -> SafeHTMLExtractionResult:
    """
    Safely extract visible text, hyperlinks, forms, and hidden indicators from HTML email.
    Completely static — zero remote network calls, zero script execution.
    """
    if not html_content or not isinstance(html_content, str):
        return SafeHTMLExtractionResult(
            visible_text="",
            extracted_links=[],
            anchor_mismatches=[],
            forms=[],
            iframes=[],
            image_sources=[],
            hidden_element_count=0,
            has_password_form=False,
            raw_html_size=0,
        )

    parser = _SafeEmailHTMLParser()
    try:
        parser.feed(html_content)
    except Exception:
        # Fallback if parser errors on unclosed syntax
        pass

    visible = " ".join(parser.text_parts)
    visible_normalized = re.sub(r"\s+", " ", visible).strip()

    mismatches = [link for link in parser.extracted_links if link.is_anchor_mismatch]
    has_pw = any(f.has_password_field for f in parser.forms)

    return SafeHTMLExtractionResult(
        visible_text=visible_normalized,
        extracted_links=parser.extracted_links,
        anchor_mismatches=mismatches,
        forms=parser.forms,
        iframes=parser.iframes,
        image_sources=parser.image_sources,
        hidden_element_count=parser.hidden_element_count,
        has_password_form=has_pw,
        raw_html_size=len(html_content.encode("utf-8", errors="replace")),
    )
