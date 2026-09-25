"""
ScamBuster ML Bridge Client

Provides a clean interface for the FastAPI backend to interact with the
trained machine learning models located in the `ml/` subsystem.
Handles path resolution, lazy loading, and error handling.
"""

import sys
import logging
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("scambuster.ml_client")

# Ensure the root ml package is in python path
ROOT_DIR = Path(__file__).resolve().parents[3]
ML_DIR = ROOT_DIR / "ml"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

# Lazy loaded predictor functions
_text_predictor = None
_url_predictor = None


def get_text_predictor():
    global _text_predictor
    if _text_predictor is None:
        try:
            from ml.inference.text_predictor import predict_text
            _text_predictor = predict_text
        except Exception as e:
            logger.error(f"Failed to load text predictor from ML subsystem: {e}")
            raise
    return _text_predictor


def get_url_predictor():
    global _url_predictor
    if _url_predictor is None:
        try:
            from ml.inference.url_predictor import predict_url
            _url_predictor = predict_url
        except Exception as e:
            logger.error(f"Failed to load URL predictor from ML subsystem: {e}")
            raise
    return _url_predictor


def analyze_text_ml(text: str) -> Dict[str, Any]:
    """
    Run text inference using the trained TF-IDF + Logistic Regression model.
    Returns dictionary with prediction, probability, spam_probability, model name, version.
    """
    try:
        predictor = get_text_predictor()
        return predictor(text)
    except Exception as e:
        logger.warning(f"ML text prediction fallback triggered: {e}")
        return {
            "prediction": "unavailable",
            "probability": 0.0,
            "spam_probability": 0.0,
            "model": "Text ML Model (Offline/Error)",
            "model_version": "1.0.0",
            "error": str(e),
        }


def analyze_url_ml(url: str) -> Dict[str, Any]:
    """
    Run URL inference using the trained Random Forest classifier.
    Returns dictionary with prediction, probability, malicious_probability, model name, version.
    """
    try:
        predictor = get_url_predictor()
        return predictor(url)
    except Exception as e:
        logger.warning(f"ML URL prediction fallback triggered: {e}")
        return {
            "prediction": "unavailable",
            "probability": 0.0,
            "malicious_probability": 0.0,
            "model": "URL ML Model (Offline/Error)",
            "model_version": "1.0.0",
            "features_used": 0,
            "error": str(e),
        }
