"""
ScamBuster — Brand Normalizer Service (Phase 10)

Normalizes brand names, strips corporate suffixes, handles leetspeak/homoglyphs
in brand references, and extracts candidate brand entities from message text
and sender headers.
"""

import re
import unicodedata
from typing import List, Optional, Set, Tuple

from app.intelligence.brands.catalog import BRAND_CATALOG, BrandRecord


# Noise terms commonly appended to brands in phishing campaigns
STRIP_SUFFIXES = {
    "support", "security", "team", "alert", "alerts", "service", "services",
    "helpdesk", "billing", "online", "login", "verify", "verification",
    "account", "accounts", "notification", "department", "desk", "center",
    "inc", "corp", "corporation", "ltd", "llc", "plc", "pvt ltd",
}

# Common leetspeak substitutions
LEET_MAP = {
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"
}


def normalize_text_for_brands(text: str) -> str:
    """Normalize text with unicode decomposition and basic leetspeak translation."""
    if not text:
        return ""
    # Unicode NFKD
    decomposed = unicodedata.normalize("NFKD", text)
    ascii_only = "".join(c for c in decomposed if not unicodedata.combining(c))
    lower = ascii_only.lower()
    # Translate leetspeak numbers that are inside words
    chars = []
    for char in lower:
        chars.append(LEET_MAP.get(char, char))
    return "".join(chars)


def extract_claimed_brands(text: str) -> List[Tuple[BrandRecord, str]]:
    """
    Search text for mentions of cataloged brands or their aliases.
    Returns list of (BrandRecord, matched_text).
    """
    if not text:
        return []

    norm_text = normalize_text_for_brands(text)
    found_brands: List[Tuple[BrandRecord, str]] = []
    seen_ids: Set[str] = set()

    for brand_id, brand in BRAND_CATALOG.items():
        if brand_id in seen_ids:
            continue

        # Check aliases from longest to shortest to prevent partial collisions
        sorted_aliases = sorted(brand.aliases | {brand_id}, key=len, reverse=True)
        for alias in sorted_aliases:
            # Word boundary search
            pattern = r"\b" + re.escape(alias) + r"\b"
            m = re.search(pattern, norm_text)
            if m:
                found_brands.append((brand, m.group(0)))
                seen_ids.add(brand_id)
                break

    return found_brands
