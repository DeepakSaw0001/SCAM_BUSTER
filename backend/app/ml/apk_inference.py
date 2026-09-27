"""
ScamBuster ML — Android APK Inference Service (Phase 07)

Thread-safe, singleton inference service for Android APK malware and trojan classification.
Loads the packaged model artifact once and serves low-latency predictions.

Security & Safety:
- Never executes or unpacks APK binary code at inference time.
- Purely evaluates static numerical feature vectors extracted by apk_analyzer.
- Fails safely with fallback outputs if model artifacts are unavailable.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

from app.features.apk_features import (
    APK_FEATURE_NAMES,
    APK_FEATURE_VERSION,
    extract_apk_feature_vector,
    extract_features_from_apk_result,
)

logger = logging.getLogger("scambuster.apk_inference")

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "apk_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "apk_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "apk_model_v1.0"


class ApkModelManager:
    """Singleton manager for loading and executing the APK malware classifier pipeline."""

    _instance: Optional["ApkModelManager"] = None

    def __init__(self):
        self.model = None
        self.feature_names = APK_FEATURE_NAMES
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "ApkModelManager":
        if cls._instance is None:
            cls._instance = ApkModelManager()
        return cls._instance

    def is_loaded(self) -> bool:
        return self.model is not None

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        target_path = MODEL_PATH
        meta_path = METADATA_PATH

        if not target_path.exists():
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "apk_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "apk_model_v1_metadata.json"
            else:
                logger.warning("APK ML model artifact not found at %s or %s", MODEL_PATH, fallback_path)
                return

        try:
            artifact = joblib.load(target_path)
            if isinstance(artifact, dict) and "pipeline" in artifact:
                self.model = artifact["pipeline"]
                self.feature_names = artifact.get("feature_names", APK_FEATURE_NAMES)
                self.model_version = artifact.get("version", DEFAULT_MODEL_VERSION)
            else:
                self.model = artifact
                self.model_version = DEFAULT_MODEL_VERSION

            if meta_path.exists():
                with open(meta_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)

            logger.info("Successfully loaded APK classifier (%s) from %s", self.model_version, target_path)
        except Exception as e:
            logger.error("Failed to load APK ML model: %s", str(e), exc_info=True)
            self.model = None

    def predict(self, analysis_result: Any) -> Dict[str, Any]:
        """
        Run inference on extracted APK static features.
        Returns a structured dictionary matching ScamBuster MLDetectionDetails schema.
        """
        if self.model is None:
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
            vec = extract_apk_feature_vector(analysis_result)
            X = np.array([vec], dtype=np.float32)

            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(X)[0]
                malware_prob = float(probs[1]) if len(probs) > 1 else float(probs[0])
            elif hasattr(self.model, "decision_function"):
                df_val = float(self.model.decision_function(X)[0])
                malware_prob = float(1.0 / (1.0 + np.exp(-df_val)))
            else:
                pred_raw = int(self.model.predict(X)[0])
                malware_prob = 1.0 if pred_raw == 1 else 0.0

            if malware_prob >= 0.65:
                pred_label = "malware"
            elif malware_prob >= 0.40:
                pred_label = "suspicious"
            else:
                pred_label = "clean"

            feat_dict = extract_features_from_apk_result(analysis_result)
            top_features = []
            for name, val in feat_dict.items():
                if name in (
                    "has_banking_overlay_cluster",
                    "has_surveillance_cluster",
                    "special_permission_count",
                    "has_dynamic_loading",
                    "has_command_execution",
                    "dangerous_permission_count",
                    "is_debug_certificate",
                ) and val > 0:
                    top_features.append({"feature": name, "value": val})

            return {
                "prediction": pred_label,
                "model_score": round(malware_prob, 4),
                "model_version": self.model_version,
                "model_probability": round(malware_prob, 4),
                "features_used": len(self.feature_names),
                "top_contributing_features": top_features[:5],
            }
        except Exception as e:
            logger.error("APK inference failure: %s", str(e), exc_info=True)
            return {
                "prediction": "error",
                "model_score": 0.0,
                "model_version": self.model_version,
                "model_probability": 0.0,
                "features_used": 0,
                "top_contributing_features": [],
            }


apk_model_manager = ApkModelManager.get_instance()


def predict_apk_risk(analysis_result: Any) -> Dict[str, Any]:
    """Public helper function for APK ML inference."""
    return apk_model_manager.predict(analysis_result)
