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
    Run text inference using the Phase 04 Calibrated LinearSVC pipeline.
    Returns dictionary with prediction, model_score, model_probability, spam_probability, model version.
    """
    try:
        from app.ml.message_inference import predict_message_threat
        res = predict_message_threat(text)
        res["spam_probability"] = res.get("model_probability", 0.0)
        res["probability"] = res.get("model_score", 0.0)
        res["model"] = "TF-IDF + Calibrated LinearSVC"
        return res
    except Exception as e:
        logger.warning(f"ML text prediction fallback triggered: {e}")
        return {
            "prediction": "unavailable",
            "probability": 0.0,
            "spam_probability": 0.0,
            "model_score": 0.0,
            "model_probability": 0.0,
            "model": "Text ML Model (Offline/Error)",
            "model_version": "message-model-1.0",
            "available": False,
            "error": str(e),
        }


def analyze_url_ml(url: str) -> Dict[str, Any]:
    """
    Run URL inference using the Phase 03 Random Forest classifier pipeline.
    Returns dictionary with prediction, model_score, model_probability, model version, and features.
    """
    try:
        from app.ml.inference import predict_url_threat
        return predict_url_threat(url)
    except Exception as e:
        logger.warning(f"ML URL prediction fallback triggered: {e}")
        return {
            "prediction": "unavailable",
            "model_score": 0.0,
            "model_probability": 0.0,
            "model_version": "url-model-1.0",
            "features_used": 0,
            "available": False,
            "error": str(e),
        }

