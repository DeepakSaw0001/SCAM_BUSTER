"""
ScamBuster ML — Message Features (Phase 04)

Provides structured feature extraction and TF-IDF vectorizer configuration
for SMS and text message models.
"""

import sys
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer

BACKEND_DIR = Path(__file__).resolve().parents[2] / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.services.message_feature_extractor import (
    ALL_MESSAGE_FEATURES,
    MESSAGE_STATISTICAL_FEATURES,
    MESSAGE_STRUCTURAL_FEATURES,
    MESSAGE_SEMANTIC_FEATURES,
    MessageFeatures,
    extract_message_features,
)

# Standardized TF-IDF parameters for text scam detection
TFIDF_CONFIG = {
    "ngram_range": (1, 2),        # Unigrams + Bigrams
    "min_df": 2,                  # Ignore rare singletons
    "max_df": 0.95,               # Ignore corpus-wide stops
    "sublinear_tf": True,         # Logarithmic term frequency scaling (1 + log(tf))
    "max_features": 5000,         # Compact, efficient vocabulary size
}


def build_tfidf_vectorizer(**overrides) -> TfidfVectorizer:
    """Return a configured TfidfVectorizer instance."""
    params = {**TFIDF_CONFIG, **overrides}
    return TfidfVectorizer(**params)
