"""
ScamBuster ML — URL Predictor

Loads the trained Random Forest URL classifier once, then exposes
a stateless `predict_url()` function for inference.

NOTE: The model classifies URLs as "benign" or "malicious" based on
structural features.  A "malicious" prediction is a statistical
signal — it does NOT constitute proof that a URL is dangerous.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.url_features import extract_url_features, extract_features_vector, FEATURE_NAMES
from utils.model_utils import load_artifact

import numpy as np

# ── lazy-loaded singletons ───────────────────────────────────────────────
_clf = None

LABEL_MAP = {0: "benign", 1: "malicious"}
MODEL_NAME = "URL Features + Random Forest"
MODEL_VERSION = "1.0.0"


def _ensure_loaded():
    global _clf
    if _clf is None:
        _clf = load_artifact("url_classifier.joblib")


def predict_url(url: str) -> dict:
    """
    Predict whether a URL is benign or malicious.

    Returns:
        {
            "prediction": "benign" | "malicious",
            "probability": float,
            "malicious_probability": float,
            "model": str,
            "model_version": str,
            "features_used": int,
            "extracted_features": dict,
        }
    """
    _ensure_loaded()

    features = extract_url_features(url)
    vec = np.array(extract_features_vector(url)).reshape(1, -1)

    pred_class = int(_clf.predict(vec)[0])
    proba = _clf.predict_proba(vec)[0]

    return {
        "prediction": LABEL_MAP[pred_class],
        "probability": float(proba[pred_class]),
        "malicious_probability": float(proba[1]),
        "model": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "features_used": len(FEATURE_NAMES),
        "extracted_features": features,
    }
