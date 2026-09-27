"""
ScamBuster ML — Web Risk Inference Service (Phase 09)

Thread-safe, singleton inference service for website, redirect, and download risk classification.
Loads the packaged model artifact once and serves low-latency statistical threat predictions.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib
import numpy as np

from app.features.web_features import (
    WEB_FEATURE_NAMES,
    WEB_FEATURE_VERSION,
    extract_web_features,
    extract_web_features_vector,
)

logger = logging.getLogger("scambuster.web_inference")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "web_risk_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "web_risk_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "web_model_v1.0"


class WebRiskModelManager:
    """Singleton manager for loading and executing the Web Risk classifier."""

    _instance: Optional["WebRiskModelManager"] = None

    def __init__(self):
        self.model = None
        self.feature_names = WEB_FEATURE_NAMES
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "WebRiskModelManager":
        if cls._instance is None:
            cls._instance = WebRiskModelManager()
        return cls._instance

    def is_loaded(self) -> bool:
        return self.model is not None

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        target_path = MODEL_PATH
        meta_path = METADATA_PATH

        if not target_path.exists():
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "web_risk_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "web_risk_model_v1_metadata.json"
            else:
                logger.warning("Web Risk ML model artifact not found at %s or %s", MODEL_PATH, fallback_path)
                return

        try:
            self.model = joblib.load(target_path)
            self.model_version = DEFAULT_MODEL_VERSION

            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
                self.model_version = self.metadata.get("model_version", DEFAULT_MODEL_VERSION)

            logger.info("Successfully loaded Web Risk classifier (%s) from %s", self.model_version, target_path)
        except Exception as e:
            logger.error("Failed to load Web Risk ML model: %s", str(e), exc_info=True)
            self.model = None

    def predict(self, web_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        Run inference on extracted web and redirect features.
        """
        if self.model is None or not web_analysis:
            return {
                "available": False,
                "prediction": "benign",
                "model_score": 0.0,
                "model_version": self.model_version,
                "features_used": len(self.feature_names),
                "top_contributing_features": [],
            }

        try:
            vec = extract_web_features_vector(web_analysis).reshape(1, -1)
            raw_pred = self.model.predict(vec)[0]
            pred_class = str(raw_pred).lower()

            # Calculate threat probability
            threat_prob = 0.0
            probs = {}
            if hasattr(self.model, "predict_proba"):
                prob_vec = self.model.predict_proba(vec)[0]
                classes = [str(c).lower() for c in getattr(self.model, "classes_", [])]
                probs = {cls_name: float(p) for cls_name, p in zip(classes, prob_vec)}
                # Threat prob is probability of non-benign
                threat_prob = sum(p for c, p in probs.items() if c != "benign")

            # Determine top contributing features
            feat_dict = extract_web_features(web_analysis)
            top_features = []
            for name, val in sorted(feat_dict.items(), key=lambda x: abs(x[1]), reverse=True):
                if val > 0:
                    top_features.append({
                        "feature": name,
                        "value": val,
                        "description": name.replace("_", " ").title(),
                    })
                    if len(top_features) >= 5:
                        break

            return {
                "available": True,
                "prediction": pred_class,
                "model_score": float(threat_prob),
                "model_probability": float(probs.get(pred_class, threat_prob)),
                "model_version": self.model_version,
                "features_used": len(self.feature_names),
                "top_contributing_features": top_features,
                "class_probabilities": probs,
            }
        except Exception as e:
            logger.error("Web risk inference failed: %s", str(e), exc_info=True)
            return {
                "available": False,
                "prediction": "unknown",
                "model_score": 0.0,
                "model_version": self.model_version,
                "features_used": len(self.feature_names),
                "top_contributing_features": [],
            }


# Singleton accessor
def predict_web_risk(web_analysis: Dict[str, Any]) -> Dict[str, Any]:
    return WebRiskModelManager.get_instance().predict(web_analysis)
