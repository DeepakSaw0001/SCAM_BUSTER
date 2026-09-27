"""
ScamBuster — Brand Intelligence Module
"""

from app.intelligence.brands.catalog import (
    BRAND_CATALOG,
    BrandRecord,
    lookup_brand_by_domain,
    lookup_brand_by_name,
)
from app.intelligence.brands.normalizer import (
    extract_claimed_brands,
    normalize_text_for_brands,
)
from app.intelligence.brands.lookalike_detector import (
    BrandMismatchFinding,
    detect_brand_domain_mismatches,
    is_lookalike_domain,
)

__all__ = [
    "BRAND_CATALOG",
    "BrandRecord",
    "lookup_brand_by_domain",
    "lookup_brand_by_name",
    "extract_claimed_brands",
    "normalize_text_for_brands",
    "BrandMismatchFinding",
    "detect_brand_domain_mismatches",
    "is_lookalike_domain",
]
