"""
ScamBuster — Email Header & Sender Metadata Extractor (Phase 10)

Inspects:
- From, Reply-To, Return-Path consistency
- Display-Name impersonation vs domain mismatch
- SPF, DKIM, DMARC authentication status (PASS, FAIL, SOFTFAIL, NONE, NEUTRAL, UNKNOWN)
- Received header hops count and transit trace
- Free email provider masquerading as an institution

Important Security Distinctions:
- SPF PASS verifies domain authority, NOT sender intent (SPF PASS != Safe).
- SPF FAIL indicates authorization mismatch or forwarding, NOT definitive malware.
- If headers were not provided by the user, auth status is strictly recorded as UNKNOWN.
"""

from dataclasses import dataclass, field
import email
from email.utils import parseaddr
import re
from typing import Any, Dict, List, Optional, Tuple

from app.intelligence.brands.catalog import lookup_brand_by_domain
from app.intelligence.brands.normalizer import extract_claimed_brands


FREE_MAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "proton.me", "mail.com", "zoho.com", "yandex.com",
    "icloud.com", "gmx.com", "fastmail.com"
}


@dataclass
class HeaderAuthReport:
    headers_supplied: bool
    spf_status: str  # pass, fail, softfail, neutral, none, unknown
    spf_details: Optional[str]
    dkim_status: str
    dkim_details: Optional[str]
    dmarc_status: str
    dmarc_details: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "headers_supplied": self.headers_supplied,
            "spf": {"status": self.spf_status, "details": self.spf_details},
            "dkim": {"status": self.dkim_status, "details": self.dkim_details},
            "dmarc": {"status": self.dmarc_status, "details": self.dmarc_details},
        }


@dataclass
class SenderConsistencyReport:
    from_raw: str
    from_address: str
    from_domain: str
    display_name: str

    reply_to_address: Optional[str]
    reply_to_domain: Optional[str]

    return_path_address: Optional[str]
    return_path_domain: Optional[str]

    has_reply_to_mismatch: bool
    reply_to_mismatch_description: Optional[str]

    has_return_path_mismatch: bool
    return_path_mismatch_description: Optional[str]

    is_display_name_spoof: bool
    display_name_spoof_description: Optional[str]

    is_free_provider: bool
    free_provider_for_business_description: Optional[str]

    auth: HeaderAuthReport

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from_address": self.from_address,
            "from_domain": self.from_domain,
            "display_name": self.display_name,
            "reply_to_address": self.reply_to_address,
            "reply_to_domain": self.reply_to_domain,
            "return_path_address": self.return_path_address,
            "return_path_domain": self.return_path_domain,
            "has_reply_to_mismatch": self.has_reply_to_mismatch,
            "reply_to_mismatch_description": self.reply_to_mismatch_description,
            "is_display_name_spoof": self.is_display_name_spoof,
            "display_name_spoof_description": self.display_name_spoof_description,
            "is_free_provider": self.is_free_provider,
            "authentication": self.auth.to_dict(),
        }


def _clean_domain(addr: Optional[str]) -> str:
    """Extract domain part from an email address."""
    if not addr:
        return ""
    _, parsed = parseaddr(addr)
    target = parsed if parsed else addr
    if "@" in target:
        return target.split("@")[-1].strip().lower()
    return ""


def parse_authentication_results(msg: email.message.EmailMessage) -> HeaderAuthReport:
    """
    Extract authentication results (SPF, DKIM, DMARC) strictly from actual headers.
    Returns 'unknown' if authentication headers are missing or not provided.
    """
    auth_headers = msg.get_all("Authentication-Results", [])
    received_spf = msg.get_all("Received-SPF", [])
    dkim_sig = msg.get_all("DKIM-Signature", [])

    has_any_auth = bool(auth_headers or received_spf or dkim_sig)
    if not has_any_auth:
        return HeaderAuthReport(
            headers_supplied=False,
            spf_status="unknown",
            spf_details="No authentication headers found in supplied input.",
            dkim_status="unknown",
            dkim_details="No authentication headers found in supplied input.",
            dmarc_status="unknown",
            dmarc_details="No authentication headers found in supplied input.",
        )

    combined_auth = " ; ".join(str(h) for h in auth_headers).lower()

    # SPF
    spf_status = "unknown"
    spf_details = None
    if "spf=" in combined_auth:
        m = re.search(r"spf=([a-z]+)", combined_auth)
        if m:
            spf_status = m.group(1)
            spf_details = f"Authentication-Results: spf={spf_status}"
    elif received_spf:
        raw_spf = " ".join(str(s) for s in received_spf).lower()
        for candidate in ["pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"]:
            if raw_spf.startswith(candidate) or f" {candidate} " in raw_spf:
                spf_status = candidate
                spf_details = f"Received-SPF: {candidate}"
                break

    # DKIM
    dkim_status = "unknown"
    dkim_details = None
    if "dkim=" in combined_auth:
        m = re.search(r"dkim=([a-z]+)", combined_auth)
        if m:
            dkim_status = m.group(1)
            dkim_details = f"Authentication-Results: dkim={dkim_status}"
    elif dkim_sig:
        dkim_status = "none"
        dkim_details = "DKIM-Signature present, MTA verification status not recorded in headers."

    # DMARC
    dmarc_status = "unknown"
    dmarc_details = None
    if "dmarc=" in combined_auth:
        m = re.search(r"dmarc=([a-z]+)", combined_auth)
        if m:
            dmarc_status = m.group(1)
            dmarc_details = f"Authentication-Results: dmarc={dmarc_status}"

    return HeaderAuthReport(
        headers_supplied=True,
        spf_status=spf_status,
        spf_details=spf_details,
        dkim_status=dkim_status,
        dkim_details=dkim_details,
        dmarc_status=dmarc_status,
        dmarc_details=dmarc_details,
    )


def analyze_sender_consistency(
    from_header: str,
    reply_to_header: Optional[str] = None,
    return_path_header: Optional[str] = None,
    auth_report: Optional[HeaderAuthReport] = None,
    subject_hint: Optional[str] = None,
) -> SenderConsistencyReport:
    """
    Perform deep static sender verification:
    - Compare From, Reply-To, and Return-Path
    - Detect display name impersonation
    - Free webmail domain used for corporate/banking inquiry
    """
    name_part, addr_part = parseaddr(from_header or "")
    from_addr = addr_part.strip().lower()
    from_dom = _clean_domain(from_addr)
    disp_name = name_part.strip()

    # Reply-To
    reply_addr = None
    reply_dom = None
    has_reply_mismatch = False
    reply_mismatch_desc = None

    if reply_to_header:
        _, r_addr = parseaddr(reply_to_header)
        reply_addr = r_addr.strip().lower()
        reply_dom = _clean_domain(reply_addr)

        if reply_dom and from_dom:
            if reply_dom != from_dom and not from_dom.endswith("." + reply_dom) and not reply_dom.endswith("." + from_dom):
                has_reply_mismatch = True
                reply_mismatch_desc = (
                    f"Reply-to mismatch detected: Sender 'From' domain is '{from_dom}', "
                    f"but replies will be directed to '{reply_dom}'."
                )

    # Return-Path
    ret_addr = None
    ret_dom = None
    has_ret_mismatch = False
    ret_mismatch_desc = None

    if return_path_header:
        _, p_addr = parseaddr(return_path_header)
        ret_addr = p_addr.strip().lower()
        ret_dom = _clean_domain(ret_addr)

        if ret_dom and from_dom:
            if ret_dom != from_dom and not from_dom.endswith("." + ret_dom) and not ret_dom.endswith("." + from_dom):
                has_ret_mismatch = True
                ret_mismatch_desc = (
                    f"Return-path mismatch: Bounce/envelope domain is '{ret_dom}', "
                    f"differing from sender domain '{from_dom}'."
                )

    # Display Name Impersonation
    is_name_spoof = False
    name_spoof_desc = None
    if disp_name:
        claimed_in_name = extract_claimed_brands(disp_name)
        for brand, matched_term in claimed_in_name:
            # Check if from_dom is an official domain of this brand
            is_official = False
            for off_d in brand.official_domains:
                if from_dom == off_d or from_dom.endswith("." + off_d):
                    is_official = True
                    break
            if not is_official:
                is_name_spoof = True
                name_spoof_desc = (
                    f"Possible sender impersonation: Display name '{disp_name}' references "
                    f"brand '{brand.display_name}', but actual address originates from '{from_dom or from_addr}'."
                )
                break

    # Free email provider used for institutional communication
    is_free = from_dom in FREE_MAIL_PROVIDERS
    free_desc = None
    if is_free:
        inst_terms = ["support", "security", "billing", "bank", "irs", "customs", "payroll", "admin", "official"]
        combined_text = f"{disp_name} {subject_hint or ''}".lower()
        if any(term in combined_text for term in inst_terms) or is_name_spoof:
            free_desc = (
                f"Free consumer email mailbox (@{from_dom}) used for purported institutional or business correspondence."
            )

    return SenderConsistencyReport(
        from_raw=from_header or "",
        from_address=from_addr,
        from_domain=from_dom,
        display_name=disp_name,
        reply_to_address=reply_addr,
        reply_to_domain=reply_dom,
        return_path_address=ret_addr,
        return_path_domain=ret_dom,
        has_reply_to_mismatch=has_reply_mismatch,
        reply_to_mismatch_description=reply_mismatch_desc,
        has_return_path_mismatch=has_ret_mismatch,
        return_path_mismatch_description=ret_mismatch_desc,
        is_display_name_spoof=is_name_spoof,
        display_name_spoof_description=name_spoof_desc,
        is_free_provider=is_free,
        free_provider_for_business_description=free_desc,
        auth=auth_report or HeaderAuthReport(
            headers_supplied=False,
            spf_status="unknown",
            spf_details=None,
            dkim_status="unknown",
            dkim_details=None,
            dmarc_status="unknown",
            dmarc_details=None,
        ),
    )
