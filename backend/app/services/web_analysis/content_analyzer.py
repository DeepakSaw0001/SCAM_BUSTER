"""
Safe HTML & Content Analyzer

Performs static analysis of HTML web pages without code execution or browser rendering.
Inspects forms, sensitive input fields (password, payment, OTP), iframe hierarchies,
external script dependencies, download triggers, and obfuscation heuristics.
"""

from html.parser import HTMLParser
import re
from typing import Any, Dict, List, Optional, Set
import urllib.parse
from app.services.web_analysis.limits import (
    MAX_EXTRACTED_FORMS,
    MAX_EXTRACTED_IFRAMES,
    MAX_EXTRACTED_SCRIPTS,
    MAX_EXTRACTED_LINKS,
)
from app.services.web_analysis.redirect_analyzer import extract_registrable_domain

# Sensitive input classification keywords
PASSWORD_KEYWORDS = {"password", "pass", "pwd", "secret", "passcode", "pin"}
OTP_KEYWORDS = {"otp", "token", "2fa", "mfa", "verification", "auth_code", "verify_code"}
PAYMENT_KEYWORDS = {"card", "creditcard", "debitcard", "cvv", "cvc", "expir", "routing", "account_number", "upi", "vpa"}
IDENTITY_KEYWORDS = {"ssn", "social_security", "national_id", "tax_id", "pan", "aadhaar", "driver_license"}

DOWNLOAD_EXTENSIONS = {
    ".apk", ".exe", ".msi", ".bat", ".cmd", ".ps1", ".sh", ".vbs",
    ".scr", ".dll", ".zip", ".rar", ".7z", ".tar.gz", ".iso", ".dmg"
}


class SafeContentParser(HTMLParser):
    """
    Fast, safe streaming HTML parser extracting structure, forms, and resources.
    """

    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.base_domain = (urllib.parse.urlparse(base_url).hostname or "").lower()
        self.base_reg_domain = extract_registrable_domain(self.base_domain)

        self.title = ""
        self._in_title = False

        self.forms: List[Dict[str, Any]] = []
        self._current_form: Optional[Dict[str, Any]] = None

        self.iframes: List[Dict[str, Any]] = []
        self.external_scripts: List[str] = []
        self.script_domains: Set[str] = set()

        self.download_links: List[Dict[str, str]] = []
        self.meta_refresh: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: List[tuple]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}

        # 1. Title tag
        if tag_lower == "title":
            self._in_title = True

        # 2. Meta tags
        elif tag_lower == "meta":
            http_equiv = attr_dict.get("http-equiv", "").lower()
            if http_equiv == "refresh":
                self.meta_refresh = attr_dict.get("content", "")

        # 3. Form tags
        elif tag_lower == "form":
            if len(self.forms) < MAX_EXTRACTED_FORMS:
                action = attr_dict.get("action", "")
                resolved_action = urllib.parse.urljoin(self.base_url, action)
                self._current_form = {
                    "action": resolved_action,
                    "method": attr_dict.get("method", "GET").upper(),
                    "has_password": False,
                    "has_otp": False,
                    "has_payment": False,
                    "has_identity": False,
                    "fields": [],
                }

        # 4. Input / Select / Textarea inside form
        elif tag_lower in ("input", "select", "textarea"):
            input_type = attr_dict.get("type", "text").lower()
            input_name = attr_dict.get("name", "").lower()
            input_id = attr_dict.get("id", "").lower()
            combined_id = f"{input_name} {input_id}".strip()

            field_info = {
                "tag": tag_lower,
                "type": input_type,
                "name": input_name or input_id,
            }

            # Check sensitivity
            is_password = input_type == "password" or any(kw in combined_id for kw in PASSWORD_KEYWORDS)
            is_otp = any(kw in combined_id for kw in OTP_KEYWORDS)
            is_payment = any(kw in combined_id for kw in PAYMENT_KEYWORDS)
            is_identity = any(kw in combined_id for kw in IDENTITY_KEYWORDS)

            if is_password:
                field_info["sensitive"] = "PASSWORD"
            elif is_otp:
                field_info["sensitive"] = "OTP"
            elif is_payment:
                field_info["sensitive"] = "PAYMENT"
            elif is_identity:
                field_info["sensitive"] = "IDENTITY"

            if self._current_form:
                if is_password:
                    self._current_form["has_password"] = True
                if is_otp:
                    self._current_form["has_otp"] = True
                if is_payment:
                    self._current_form["has_payment"] = True
                if is_identity:
                    self._current_form["has_identity"] = True
                self._current_form["fields"].append(field_info)
            elif is_password or is_payment:
                # Standalone credential field not enclosed in <form> tag
                standalone_form = {
                    "action": self.base_url,
                    "method": "UNKNOWN",
                    "has_password": is_password,
                    "has_otp": is_otp,
                    "has_payment": is_payment,
                    "has_identity": is_identity,
                    "fields": [field_info],
                }
                self.forms.append(standalone_form)

        # 5. iframes
        elif tag_lower == "iframe":
            if len(self.iframes) < MAX_EXTRACTED_IFRAMES:
                src = attr_dict.get("src", "")
                resolved_src = urllib.parse.urljoin(self.base_url, src) if src else ""
                iframe_domain = (urllib.parse.urlparse(resolved_src).hostname or "").lower() if resolved_src else ""
                iframe_reg = extract_registrable_domain(iframe_domain)

                # Check if hidden
                style = attr_dict.get("style", "").lower().replace(" ", "")
                width = attr_dict.get("width", "")
                height = attr_dict.get("height", "")
                is_hidden = (
                    "display:none" in style
                    or "visibility:hidden" in style
                    or width in ("0", "0px", "1", "1px")
                    or height in ("0", "0px", "1", "1px")
                )

                self.iframes.append({
                    "src": resolved_src,
                    "domain": iframe_domain,
                    "is_cross_domain": bool(iframe_reg and iframe_reg != self.base_reg_domain),
                    "is_hidden": is_hidden,
                    "sandbox": attr_dict.get("sandbox"),
                })

        # 6. Scripts
        elif tag_lower == "script":
            src = attr_dict.get("src", "")
            if src and len(self.external_scripts) < MAX_EXTRACTED_SCRIPTS:
                resolved_script = urllib.parse.urljoin(self.base_url, src)
                script_domain = (urllib.parse.urlparse(resolved_script).hostname or "").lower()
                self.external_scripts.append(resolved_script)
                if script_domain:
                    self.script_domains.add(script_domain)

        # 7. Anchor links (detect download intent)
        elif tag_lower == "a":
            href = attr_dict.get("href", "")
            has_download_attr = "download" in attr_dict
            if href and (has_download_attr or any(href.lower().endswith(ext) for ext in DOWNLOAD_EXTENSIONS)):
                if len(self.download_links) < MAX_EXTRACTED_LINKS:
                    resolved_link = urllib.parse.urljoin(self.base_url, href)
                    self.download_links.append({
                        "url": resolved_link,
                        "download_attr": attr_dict.get("download", ""),
                        "filename_hint": resolved_link.split("/")[-1].split("?")[0],
                    })

    def handle_endtag(self, tag: str):
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
        elif tag_lower == "form":
            if self._current_form:
                self.forms.append(self._current_form)
                self._current_form = None

    def handle_data(self, data: str):
        if self._in_title and not self.title:
            self.title = data.strip()[:256]


def analyze_html_content(html_text: str, current_url: str) -> Dict[str, Any]:
    """
    Parse HTML safely and return structural security features and credential exposure metrics.
    """
    if not html_text or not isinstance(html_text, str):
        return {
            "title": "",
            "form_count": 0,
            "password_form_count": 0,
            "payment_form_count": 0,
            "otp_form_count": 0,
            "has_credential_form": False,
            "iframe_count": 0,
            "hidden_iframe_count": 0,
            "cross_domain_iframe_count": 0,
            "external_script_count": 0,
            "script_domains": [],
            "download_links_count": 0,
            "download_links": [],
            "obfuscation_indicators": [],
        }

    # Limit parsed text length to 2MB
    safe_text = html_text[:2 * 1024 * 1024]

    parser = SafeContentParser(current_url)
    try:
        parser.feed(safe_text)
    except Exception:
        # html.parser handles most malformed HTML smoothly
        pass

    # Tally metrics
    password_forms = sum(1 for f in parser.forms if f.get("has_password"))
    payment_forms = sum(1 for f in parser.forms if f.get("has_payment"))
    otp_forms = sum(1 for f in parser.forms if f.get("has_otp"))
    has_credential_form = (password_forms > 0) or (payment_forms > 0) or (otp_forms > 0)

    hidden_iframes = sum(1 for i in parser.iframes if i.get("is_hidden"))
    cross_domain_iframes = sum(1 for i in parser.iframes if i.get("is_cross_domain"))

    # Inspect for static script obfuscation patterns
    obfuscation_indicators: List[str] = []
    lower_html = safe_text.lower()
    if "eval(" in lower_html and ("fromcharcode" in lower_html or "unescape" in lower_html):
        obfuscation_indicators.append("Dynamic evaluation with encoded character primitives (eval + fromCharCode/unescape)")
    if "document.write(unescape(" in lower_html:
        obfuscation_indicators.append("Legacy document.write with unescaped payload insertion")
    if re.search(r"\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}\\x[0-9a-f]{2}", lower_html):
        obfuscation_indicators.append("Concentrated hexadecimal escape sequences detected in page content")

    return {
        "title": parser.title,
        "form_count": len(parser.forms),
        "password_form_count": password_forms,
        "payment_form_count": payment_forms,
        "otp_form_count": otp_forms,
        "has_credential_form": has_credential_form,
        "forms": parser.forms[:10],  # Include top 10 for inspection without bloating payload
        "iframe_count": len(parser.iframes),
        "hidden_iframe_count": hidden_iframes,
        "cross_domain_iframe_count": cross_domain_iframes,
        "iframes": parser.iframes[:10],
        "external_script_count": len(parser.external_scripts),
        "script_domains": sorted(list(parser.script_domains))[:20],
        "download_links_count": len(parser.download_links),
        "download_links": parser.download_links[:10],
        "meta_refresh": parser.meta_refresh,
        "obfuscation_indicators": obfuscation_indicators,
    }
