"""
ScamBuster ML — Text Features

For the text/SMS model the main feature representation is TF-IDF.
This module wraps sklearn's TfidfVectorizer so training and inference
share exactly the same configuration.
"""

from sklearn.feature_extraction.text import TfidfVectorizer

# Default TF-IDF hyper-parameters shared by training and inference.
TFIDF_PARAMS = {
    "max_features": 5000,
    "ngram_range": (1, 2),       # unigrams + bigrams
    "min_df": 2,
    "max_df": 0.95,
    "sublinear_tf": True,
}


def build_tfidf_vectorizer(**overrides) -> TfidfVectorizer:
    """Return a fresh TfidfVectorizer with the project defaults."""
    params = {**TFIDF_PARAMS, **overrides}
    return TfidfVectorizer(**params)
