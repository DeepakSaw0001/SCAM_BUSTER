"""
ScamBuster ML — Android APK Privacy Inference Service (Phase 08)

Thread-safe, singleton inference service for Android APK privacy-risk tier classification.
Loads the packaged model artifact once and serves low-latency predictions.

Security & Safety:
- Never executes or unpacks APK binary code at inference time.
- Purely evaluates static numerical feature vectors extracted by apk_privacy_features.
- Fails safely with fallback outputs if model artifacts are unavailable.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from app.features.apk_privacy_features import (
    PRIVACY_FEATURE_NAMES,
    PRIVACY_FEATURE_VERSION,
    extract_privacy_feature_vector,
    extract_privacy_features,
)

logger = logging.getLogger("scambuster.apk_privacy_inference")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "apk_privacy_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "apk_privacy_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "apk_privacy_model_v1.0"


class ApkPrivacyModelManager:
    """Singleton manager for loading and executing the APK privacy tier classifier."""

    _instance: Optional["ApkPrivacyModelManager"] = None

    def __init__(self):
        self.model = None
        self.feature_names = PRIVACY_FEATURE_NAMES
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "ApkPrivacyModelManager":
        if cls._instance is None:
            cls._instance = ApkPrivacyModelManager()
        return cls._instance

    def is_loaded(self) -> bool:
        return self.model is not None

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        target_path = MODEL_PATH
        meta_path = METADATA_PATH

        if not target_path.exists():
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "apk_privacy_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "apk_privacy_model_v1_metadata.json"
            else:
                logger.warning("APK Privacy ML model artifact not found at %s or %s", MODEL_PATH, fallback_path)
                return

        try:
            artifact = joblib.load(target_path)
            if isinstance(artifact, dict) and "pipeline" in artifact:
                self.model = artifact["pipeline"]
                self.feature_names = artifact.get("feature_names", PRIVACY_FEATURE_NAMES)
                self.model_version = artifact.get("version", DEFAULT_MODEL_VERSION)
            else:
                self.model = artifact
                self.model_version = DEFAULT_MODEL_VERSION

            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            logger.info("Successfully loaded APK privacy classifier (%s) from %s", self.model_version, target_path)
        except Exception as e:
            logger.error("Failed to load APK privacy ML model: %s", str(e), exc_info=True)
            self.model = None

    def predict(self, analysis_result: Any) -> Dict[str, Any]:
        """
        Run inference on extracted APK static privacy features.
        """
        if self.model is None:
            logger.warning("APK privacy model not loaded; providing rule fallback prediction.")
            return {
                "prediction": "medium",
                "model_score": 0.50,
                "model_version": self.model_version,
                "model_probability": 0.50,
                "available": False,
                "features_used": len(self.feature_names),
            }

        try:
            vec = extract_privacy_feature_vector(analysis_result)
            X = np.array(vec).reshape(1, -1)

            pred_class = str(self.model.predict(X)[0])
            prob_dict = {}

            if hasattr(self.model, "predict_proba"):
                classes = list(getattr(self.model, "classes_", ["critical", "high", "low", "medium"]))
                probas = self.model.predict_proba(X)[0]
                prob_dict = {str(c): float(p) for c, p in zip(classes, probas)}
                max_prob = float(np.max(probas))
            else:
                max_prob = 1.0

            # Map tier to normalized privacy score (0.0 to 1.0)
            score_map = {"low": 0.15, "medium": 0.40, "high": 0.70, "critical": 0.90}
            base_score = score_map.get(pred_class, 0.50)

            return {
                "prediction": pred_class,
                "model_score": base_score,
                "model_version": self.model_version,
                "model_probability": round(max_prob, 4),
                "tier_probabilities": prob_dict,
                "available": True,
                "features_used": len(self.feature_names),
            }
        except Exception as e:
            logger.error("APK privacy inference failure: %s", str(e), exc_info=True)
            return {
                "prediction": "error",
                "model_score": 0.0,
                "model_version": self.model_version,
                "available": False,
                "error": str(e),
            }


def predict_apk_privacy(analysis_result: Any) -> Dict[str, Any]:
    """Module-level convenience wrapper for APK privacy classification."""
    return ApkPrivacyModelManager.get_instance().predict(analysis_result)
