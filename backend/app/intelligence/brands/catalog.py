"""
ScamBuster — Authoritative Brand Intelligence Catalog (Phase 10)

Stores verified official brand records, primary domains, official subdomains,
and sector categorization. Used for deterministic brand impersonation
and brand-domain mismatch detection.

Rules:
- Only verified, legitimate official domains are listed.
- Categorized by sector (Banking, Tech/Cloud, Delivery, Payment, Government, Streaming).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, FrozenSet


@dataclass(frozen=True)
class BrandRecord:
    canonical_id: str
    display_name: str
    sector: str  # banking, payment, delivery, tech, government, social, streaming, retail
    official_domains: FrozenSet[str]
    aliases: FrozenSet[str] = field(default_factory=frozenset)
    known_sender_prefixes: FrozenSet[str] = field(default_factory=frozenset)


# Verified global and regional institutions catalog
BRAND_CATALOG: Dict[str, BrandRecord] = {
    # Payments & FinTech
    "paypal": BrandRecord(
        canonical_id="paypal",
        display_name="PayPal",
        sector="payment",
        official_domains=frozenset({"paypal.com", "paypal.me", "paypal-communication.com"}),
        aliases=frozenset({"paypal", "pay pal", "paypal support", "paypal security"}),
        known_sender_prefixes=frozenset({"service", "support", "member", "alerts"}),
    ),
    "stripe": BrandRecord(
        canonical_id="stripe",
        display_name="Stripe",
        sector="payment",
        official_domains=frozenset({"stripe.com"}),
        aliases=frozenset({"stripe", "stripe payments", "stripe billing"}),
    ),
    # Banking
    "chase": BrandRecord(
        canonical_id="chase",
        display_name="JPMorgan Chase",
        sector="banking",
        official_domains=frozenset({"chase.com", "jpmorganchase.com", "jpmorgan.com"}),
        aliases=frozenset({"chase", "chase bank", "jpmorgan chase", "chase fraud alert"}),
    ),
    "wells_fargo": BrandRecord(
        canonical_id="wells_fargo",
        display_name="Wells Fargo",
        sector="banking",
        official_domains=frozenset({"wellsfargo.com"}),
        aliases=frozenset({"wells fargo", "wellsfargo", "wells fargo bank"}),
    ),
    "bank_of_america": BrandRecord(
        canonical_id="bank_of_america",
        display_name="Bank of America",
        sector="banking",
        official_domains=frozenset({"bankofamerica.com", "bofa.com"}),
        aliases=frozenset({"bank of america", "bofa", "boa", "bankofamerica"}),
    ),
    "sbi": BrandRecord(
        canonical_id="sbi",
        display_name="State Bank of India",
        sector="banking",
        official_domains=frozenset({"onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"}),
        aliases=frozenset({"state bank of india", "sbi", "onlinesbi", "sbi yono", "yono sbi"}),
    ),
    "hdfc": BrandRecord(
        canonical_id="hdfc",
        display_name="HDFC Bank",
        sector="banking",
        official_domains=frozenset({"hdfcbank.com"}),
        aliases=frozenset({"hdfc bank", "hdfc", "hdfc netbanking"}),
    ),
    "icici": BrandRecord(
        canonical_id="icici",
        display_name="ICICI Bank",
        sector="banking",
        official_domains=frozenset({"icicibank.com"}),
        aliases=frozenset({"icici bank", "icici", "icici netbanking", "imobile"}),
    ),
    # Delivery & Logistics
    "usps": BrandRecord(
        canonical_id="usps",
        display_name="United States Postal Service",
        sector="delivery",
        official_domains=frozenset({"usps.com", "usps.gov"}),
        aliases=frozenset({"usps", "u.s. postal service", "united states postal service", "postal service"}),
    ),
    "fedex": BrandRecord(
        canonical_id="fedex",
        display_name="FedEx",
        sector="delivery",
        official_domains=frozenset({"fedex.com"}),
        aliases=frozenset({"fedex", "federal express", "fedex express"}),
    ),
    "dhl": BrandRecord(
        canonical_id="dhl",
        display_name="DHL",
        sector="delivery",
        official_domains=frozenset({"dhl.com", "dhl.de", "express.dhl"}),
        aliases=frozenset({"dhl", "dhl express", "dhl parcel"}),
    ),
    "ups": BrandRecord(
        canonical_id="ups",
        display_name="UPS",
        sector="delivery",
        official_domains=frozenset({"ups.com"}),
        aliases=frozenset({"ups", "united parcel service"}),
    ),
    "india_post": BrandRecord(
        canonical_id="india_post",
        display_name="India Post",
        sector="delivery",
        official_domains=frozenset({"indiapost.gov.in"}),
        aliases=frozenset({"india post", "indiapost", "post department"}),
    ),
    # Tech / Cloud / Identity
    "google": BrandRecord(
        canonical_id="google",
        display_name="Google",
        sector="tech",
        official_domains=frozenset({"google.com", "gmail.com", "accounts.google.com", "googlemail.com", "youtube.com"}),
        aliases=frozenset({"google", "google security", "google workspace", "gmail", "google account"}),
    ),
    "microsoft": BrandRecord(
        canonical_id="microsoft",
        display_name="Microsoft",
        sector="tech",
        official_domains=frozenset({"microsoft.com", "live.com", "outlook.com", "office.com", "microsoftonline.com"}),
        aliases=frozenset({"microsoft", "microsoft 365", "office 365", "outlook", "microsoft account", "msft"}),
    ),
    "apple": BrandRecord(
        canonical_id="apple",
        display_name="Apple",
        sector="tech",
        official_domains=frozenset({"apple.com", "icloud.com"}),
        aliases=frozenset({"apple", "apple id", "icloud", "apple security", "apple support"}),
    ),
    "amazon": BrandRecord(
        canonical_id="amazon",
        display_name="Amazon",
        sector="retail",
        official_domains=frozenset({"amazon.com", "amazon.co.uk", "amazon.in", "amazon.de", "amazon.ca"}),
        aliases=frozenset({"amazon", "amazon prime", "amazon order", "amazon customer service"}),
    ),
    "netflix": BrandRecord(
        canonical_id="netflix",
        display_name="Netflix",
        sector="streaming",
        official_domains=frozenset({"netflix.com"}),
        aliases=frozenset({"netflix", "netflix support", "netflix billing"}),
    ),
    # Government & Tax
    "irs": BrandRecord(
        canonical_id="irs",
        display_name="Internal Revenue Service",
        sector="government",
        official_domains=frozenset({"irs.gov"}),
        aliases=frozenset({"irs", "internal revenue service", "irs tax refund"}),
    ),
    "incometax_india": BrandRecord(
        canonical_id="incometax_india",
        display_name="Income Tax Department of India",
        sector="government",
        official_domains=frozenset({"incometax.gov.in", "incometaxindia.gov.in"}),
        aliases=frozenset({"income tax department", "income tax india", "it department", "tax refund india"}),
    ),
}


def lookup_brand_by_domain(domain: str) -> Optional[BrandRecord]:
    """Find brand associated with a domain if it is an official domain."""
    clean_dom = domain.lower().strip().lstrip("www.")
    for brand in BRAND_CATALOG.values():
        for off_dom in brand.official_domains:
            if clean_dom == off_dom or clean_dom.endswith("." + off_dom):
                return brand
    return None


def lookup_brand_by_name(name: str) -> Optional[BrandRecord]:
    """Find brand by display name or registered alias."""
    clean_name = name.lower().strip()
    for brand in BRAND_CATALOG.values():
        if clean_name == brand.canonical_id or clean_name in brand.aliases:
            return brand
    return None
