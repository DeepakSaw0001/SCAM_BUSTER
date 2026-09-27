"""
ScamBuster ML — Email Features (Phase 05)

Provides structured feature extraction and TF-IDF vectorizer configuration
for email scam and phishing classification.
"""

from typing import Any, Dict
from sklearn.feature_extraction.text import TfidfVectorizer

# Standardized TF-IDF parameters for email phishing detection
# Optimized for full email body and subject text vocabulary
EMAIL_TFIDF_CONFIG: Dict[str, Any] = {
    "ngram_range": (1, 2),        # Unigrams + Bigrams
    "min_df": 2,                  # Ignore rare singletons
    "max_df": 0.90,               # Ignore ubiquitous stops
    "sublinear_tf": True,         # Logarithmic term frequency scaling (1 + log(tf))
    "max_features": 8000,         # Rich vocabulary for email phishing patterns
    "strip_accents": "unicode",
    "stop_words": "english",
}


def build_email_tfidf_vectorizer(**overrides) -> TfidfVectorizer:
    """Return a configured TfidfVectorizer instance for email text."""
    params = {**EMAIL_TFIDF_CONFIG, **overrides}
    return TfidfVectorizer(**params)
