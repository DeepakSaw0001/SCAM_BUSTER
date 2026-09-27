"""
ScamBuster ML Preprocessing Layer (Phase 03)

Ensures that feature extraction at inference time exactly matches the schema,
feature ordering, and types used during model training.

CRITICAL: Reuses the common `app.services.url_feature_extractor` to guarantee zero
feature skew between training and inference.
"""

from typing import Dict, Any, Optional
import pandas as pd

from app.services.url_feature_extractor import (
    URL_FEATURE_NAMES,
    UrlFeatures,
    extract_feature_dict,
)


def format_features_as_dataframe(feature_dict: Dict[str, Any]) -> pd.DataFrame:
    """
    Format a raw feature dictionary into a single-row pandas DataFrame
    strictly conforming to URL_FEATURE_NAMES column order and expected types.
    """
    row = {}
    for col in URL_FEATURE_NAMES:
        val = feature_dict.get(col, 0)
        # Convert boolean flags explicitly to integers for scikit-learn compatibility
        if isinstance(val, bool):
            row[col] = int(val)
        elif isinstance(val, (int, float)):
            row[col] = val
        else:
            try:
                row[col] = float(val)
            except (ValueError, TypeError):
                row[col] = 0.0

    return pd.DataFrame([row], columns=URL_FEATURE_NAMES)


def preprocess_url_for_inference(
    url: str,
    extracted_features: Optional[UrlFeatures] = None
) -> pd.DataFrame:
    """
    Preprocess a URL for ML inference.
    If `extracted_features` is already provided (e.g., from Phase 02 extractor),
    it converts it directly, avoiding duplicate parsing.
    Otherwise, extracts features cleanly.
    """
    if extracted_features is not None:
        f_dict = extracted_features.model_dump()
        # Compute derived ratios if needed
        f_dict["has_at_symbol"] = f_dict.get("has_at_symbol", False)
        f_dict["has_double_slash_redirect"] = f_dict.get("has_double_slash_redirect", False)
        f_dict["digit_ratio"] = (
            round(f_dict.get("number_of_digits", 0) / f_dict["url_length"], 4)
            if f_dict.get("url_length", 0) > 0
            else 0.0
        )
    else:
        f_dict = extract_feature_dict(url)

    return format_features_as_dataframe(f_dict)
