"""
ScamBuster — Social Engineering Security Module
"""

from app.security.social_engineering.taxonomy import (
    SocialEngineeringCategory,
    CategoryMetadata,
    TAXONOMY_REGISTRY,
    get_category_metadata,
)

__all__ = [
    "SocialEngineeringCategory",
    "CategoryMetadata",
    "TAXONOMY_REGISTRY",
    "get_category_metadata",
]
