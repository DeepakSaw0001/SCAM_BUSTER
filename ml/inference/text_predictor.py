"""
ScamBuster ML — Text Predictor

Loads the trained TF-IDF vectorizer and Logistic Regression model
once, then exposes a stateless `predict_text()` function for inference.

The prediction result includes the class label, probability, and
model metadata so downstream consumers know what produced the score.

NOTE: The model was trained on the UCI SMS Spam Collection whose
labels are "ham" (not spam) and "spam".  We preserve that terminology
rather than renaming "spam" to "scam", which would be academically
misleading.  "spam" is a statistical signal — it does not prove
that a message is a scam.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.text_preprocessor import clean_text
from utils.model_utils import load_artifact

# ── lazy-loaded singletons ───────────────────────────────────────────────
_clf = None
_vectorizer = None

LABEL_MAP = {0: "ham", 1: "spam"}
MODEL_NAME = "TF-IDF + Logistic Regression"
MODEL_VERSION = "1.0.0"


def _ensure_loaded():
    global _clf, _vectorizer
    if _clf is None:
        _clf = load_artifact("text_classifier.joblib")
        _vectorizer = load_artifact("text_vectorizer.joblib")


def predict_text(text: str) -> dict:
    """
    Predict whether a message is ham or spam.

    Returns:
        {
            "prediction": "ham" | "spam",
            "probability": float,          # probability of the predicted class
            "spam_probability": float,     # probability specifically for the spam class
            "model": str,
            "model_version": str,
            "preprocessed_input": str,
        }
    """
    _ensure_loaded()

    cleaned = clean_text(text)
    vec = _vectorizer.transform([cleaned])
    pred_class = int(_clf.predict(vec)[0])
    proba = _clf.predict_proba(vec)[0]

    return {
        "prediction": LABEL_MAP[pred_class],
        "probability": float(proba[pred_class]),
        "spam_probability": float(proba[1]),
        "model": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "preprocessed_input": cleaned,
    }
