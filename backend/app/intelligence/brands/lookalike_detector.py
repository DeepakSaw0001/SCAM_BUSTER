"""
ScamBuster — Brand Lookalike & Mismatch Detector (Phase 10)

Detects:
1. Brand-Domain Mismatch: A message or sender claims a known brand (e.g., PayPal),
   but links or originating email addresses resolve to an unrelated domain.
2. Typosquatting & Lookalike Domains: Lookalike domains that mimic verified brand domains
   using string distance, character additions (hyphenated combos), or TLD swaps.
3. Homoglyph abuse in domain representations.
"""

from dataclasses import dataclass
import difflib
import re
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from app.intelligence.brands.catalog import BRAND_CATALOG, BrandRecord, lookup_brand_by_domain
from app.intelligence.brands.normalizer import extract_claimed_brands, normalize_text_for_brands


# Homoglyph lookalike characters common in punycode / phishing domains
HOMOGLYPH_MAP = {
    "а": "a", "с": "c", "е": "e", "о": "o", "р": "p", "ѕ": "s", "х": "x", "у": "y",
    "і": "i", "ј": "j", "0": "o", "1": "l", "vv": "w", "rn": "m", "cl": "d"
}


@dataclass
class BrandMismatchFinding:
    brand: BrandRecord
    claimed_context: str  # e.g. "Display name: 'PayPal Alerts'" or "Message body claims 'Chase'"
    conflicting_domain: str
    target_type: str  # "sender_domain", "reply_to_domain", "link_destination"
    is_lookalike: bool
    description: str
    severity: str  # HIGH or CRITICAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "brand": self.brand.display_name,
            "sector": self.brand.sector,
            "claimed_context": self.claimed_context,
            "conflicting_domain": self.conflicting_domain,
            "target_type": self.target_type,
            "is_lookalike": self.is_lookalike,
            "description": self.description,
            "severity": self.severity,
        }


def _extract_core_domain(domain_str: str) -> str:
    """Extract standard 2nd-level domain (e.g. 'paypal.com' from 'secure.login.paypal.com')."""
    if not domain_str:
        return ""
    parts = domain_str.lower().strip().split(".")
    if len(parts) >= 2:
        # Simple multi-part TLD check (.co.in, .gov.in, etc.)
        if len(parts) >= 3 and parts[-2] in {"co", "gov", "ac", "org", "net", "com"} and len(parts[-1]) == 2:
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return domain_str.lower().strip()


def is_lookalike_domain(candidate_domain: str, official_domains: Set[str]) -> Tuple[bool, Optional[str]]:
    """
    Check if candidate_domain is an obvious typosquat or lookalike of any official domain.
    E.g. 'paypa1.com', 'chase-security.com', 'apple-verify.net', 'arnazon.com'.
    """
    cand_core = _extract_core_domain(candidate_domain)
    cand_base = cand_core.split(".")[0] if "." in cand_core else cand_core

    for off in official_domains:
        off_core = _extract_core_domain(off)
        off_base = off_core.split(".")[0] if "." in off_core else off_core

        if cand_core == off_core:
            return False, None  # Exact match, not a lookalike!

        # 1. Combosquatting: brand name embedded with hyphens/security words (e.g. 'paypal-update.com')
        if off_base in cand_base and off_base != cand_base:
            suspicious_words = {"login", "verify", "secure", "update", "account", "support", "alert", "service", "billing"}
            if any(w in cand_base for w in suspicious_words) or "-" in cand_base:
                return True, f"Combosquatting: domain contains brand '{off_base}' paired with security/login terminology."

        # 2. Character substitution / typosquatting (e.g. arnazon -> amazon, paypa1 -> paypal)
        # Normalize homoglyphs in candidate
        normalized_cand = cand_base
        for hg, rep in HOMOGLYPH_MAP.items():
            normalized_cand = normalized_cand.replace(hg, rep)

        if normalized_cand == off_base:
            return True, f"Homoglyph/Character substitution spoofing brand '{off_base}'."

        # String similarity check for typosquats (distance <= 2 for short brand names)
        ratio = difflib.SequenceMatcher(None, cand_base, off_base).ratio()
        if ratio >= 0.82 and len(off_base) >= 4:
            return True, f"High lexical similarity ({int(round(ratio*100))}%) to official brand '{off_base}'."

    return False, None


def detect_brand_domain_mismatches(
    claimed_text: str,
    domains: List[Tuple[str, str]],  # List of (domain, target_type) e.g. [("attacker.com", "sender_domain")]
    sender_display_name: Optional[str] = None,
) -> List[BrandMismatchFinding]:
    """
    Correlate claimed brand identity against candidate domains (sender domain, reply-to, and link destinations).
    """
    findings: List[BrandMismatchFinding] = []

    # 1. Extract brands claimed in sender display name
    brands_from_name = extract_claimed_brands(sender_display_name or "")
    # 2. Extract brands claimed in message body / subject
    brands_from_text = extract_claimed_brands(claimed_text)
    seen_ids = set()
    all_claimed = []
    for b, term in (brands_from_name + brands_from_text):
        if b.canonical_id not in seen_ids:
            seen_ids.add(b.canonical_id)
            all_claimed.append((b, term))

    for brand, matched_term in all_claimed:
        is_display_name_source = any(brand.canonical_id == b[0].canonical_id for b in brands_from_name)

        for raw_domain, target_type in domains:
            if not raw_domain:
                continue

            clean_dom = raw_domain.lower().strip().lstrip("www.")

            # Check if clean_dom is an official domain of this brand
            is_official = False
            for off_dom in brand.official_domains:
                if clean_dom == off_dom or clean_dom.endswith("." + off_dom):
                    is_official = True
                    break

            if is_official:
                # Legitimate match, no mismatch!
                continue

            # Mismatch detected! Check if it's also a deceptive lookalike domain
            lookalike, lookalike_reason = is_lookalike_domain(clean_dom, brand.official_domains)

            context_desc = (
                f"Display name claims '{matched_term}'"
                if is_display_name_source
                else f"Message body references '{matched_term}'"
            )

            if lookalike:
                desc = (
                    f"Brand Lookalike Detected: {context_desc}, but {target_type} '{clean_dom}' "
                    f"is a deceptive lookalike domain of {brand.display_name}. {lookalike_reason}"
                )
                severity = "CRITICAL"
            else:
                desc = (
                    f"Brand-Domain Mismatch: {context_desc}, but {target_type} '{clean_dom}' "
                    f"does NOT belong to verified domains for {brand.display_name} ({', '.join(sorted(brand.official_domains)[:3])})."
                )
                severity = "HIGH"

            findings.append(
                BrandMismatchFinding(
                    brand=brand,
                    claimed_context=context_desc,
                    conflicting_domain=clean_dom,
                    target_type=target_type,
                    is_lookalike=lookalike,
                    description=desc,
                    severity=severity,
                )
            )

    return findings
