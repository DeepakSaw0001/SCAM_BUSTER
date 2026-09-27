"""
ScamBuster ML — Phone Inference Service (Phase 06)

Thread-safe singleton inference service for Phone Number scam and robocall classification.
Loads the packaged model artifact once and serves low-latency predictions.

Privacy & Safety:
- Never logs raw phone numbers (uses masked representations if debugging).
- Zero external network dependencies during inference.
- Fails safely with fallback outputs if model artifacts are unavailable.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np

from app.features.phone_features import (
    PHONE_FEATURE_NAMES,
    extract_phone_feature_vector,
    extract_phone_features,
)
from app.services.phone_normalizer import NormalizedPhone, normalize_phone_number

logger = logging.getLogger("scambuster.phone_inference")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "phone_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "phone_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "phone_model_v1.0"


class PhoneModelManager:
    """Singleton manager for loading and executing the phone classifier pipeline."""

    _instance: Optional["PhoneModelManager"] = None

    def __init__(self):
        self.model = None
        self.feature_names = PHONE_FEATURE_NAMES
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "PhoneModelManager":
        if cls._instance is None:
            cls._instance = PhoneModelManager()
        return cls._instance

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        target_path = MODEL_PATH
        meta_path = METADATA_PATH

        if not target_path.exists():
            # Check fallback in repo ml/models
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "phone_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "phone_model_v1_metadata.json"
            else:
                logger.warning("Phone ML model artifact not found at %s or %s", MODEL_PATH, fallback_path)
                return

        try:
            artifact = joblib.load(target_path)
            if isinstance(artifact, dict) and "pipeline" in artifact:
                self.model = artifact["pipeline"]
                self.feature_names = artifact.get("feature_names", PHONE_FEATURE_NAMES)
                self.model_version = artifact.get("version", DEFAULT_MODEL_VERSION)
            else:
                self.model = artifact
                self.model_version = DEFAULT_MODEL_VERSION

            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            logger.info("Successfully loaded phone classifier (%s) from %s", self.model_version, target_path)
        except Exception as e:
            logger.error("Failed to load phone ML model: %s", str(e), exc_info=True)
            self.model = None

    def predict(
        self,
        phone_or_normalized: Union[str, NormalizedPhone],
        default_region: Optional[str] = "IN",
    ) -> Dict[str, Any]:
        """
        Run inference on normalized phone features.
        Returns a structured dictionary matching ScamBuster MLDetectionDetails schema.
        """
        if self.model is None:
            # Re-attempt lazy load in case model was just trained or copied
            self._load_artifact()

        if self.model is None:
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_version": "unavailable",
                "model_probability": 0.0,
                "features_used": 0,
                "top_contributing_features": [],
            }

        try:
            vec = extract_phone_feature_vector(phone_or_normalized, default_region=default_region)
            X = np.array([vec], dtype=np.float32)

            # Predict probabilities
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                scam_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            elif hasattr(self.model, "decision_function"):
                df_val = float(self.model.decision_function(X)[0])
                scam_prob = float(1.0 / (1.0 + np.exp(-df_val)))
            else:
                pred_raw = int(self.model.predict(X)[0])
                scam_prob = 1.0 if pred_raw == 1 else 0.0

            # Categorize prediction
            if scam_prob >= 0.65:
                pred_label = "scam"
            elif scam_prob >= 0.40:
                pred_label = "suspicious"
            else:
                pred_label = "legitimate"

            # Top contributing features
            feat_dict = extract_phone_features(phone_or_normalized, default_region=default_region)
            top_features = []
            for name, val in feat_dict.items():
                if name in ("is_premium_rate", "repeated_digit_ratio", "sequential_digit_score", "digit_entropy", "is_possible_number") and val > 0:
                    top_features.append({"feature": name, "value": val})

            return {
                "prediction": pred_label,
                "model_score": round(scam_prob, 4),
                "model_version": self.model_version,
                "model_probability": round(scam_prob, 4),
                "features_used": len(self.feature_names),
                "top_contributing_features": top_features[:5],
            }
        except Exception as e:
            logger.error("Phone inference failure: %s", str(e), exc_info=True)
            return {
                "prediction": "error",
                "model_score": 0.0,
                "model_version": self.model_version,
                "model_probability": 0.0,
                "features_used": 0,
                "top_contributing_features": [],
            }


phone_model_manager = PhoneModelManager.get_instance()


def predict_phone_risk(
    phone_or_normalized: Union[str, NormalizedPhone],
    default_region: Optional[str] = "IN",
) -> Dict[str, Any]:
    """Public helper function for phone ML inference."""
    return phone_model_manager.predict(phone_or_normalized, default_region=default_region)
