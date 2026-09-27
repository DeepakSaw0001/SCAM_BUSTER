"""
ScamBuster ML Inference Service (Phase 03)

Loads the trusted, packaged model artifact once and serves thread-safe,
high-performance predictions on structured URL features.

Security & Integrity:
- Loads ONLY trusted local model artifacts from the application package.
- Reuses common URL feature extractor (app.services.url_feature_extractor).
- Zero outbound network requests (no URL fetching / zero SSRF).
- Graceful degradation: If model artifact is unavailable, returns safe fallback.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional
import joblib

from app.ml.preprocessing import preprocess_url_for_inference
from app.services.url_feature_extractor import UrlFeatures

logger = logging.getLogger("scambuster.ml_inference")

# Canonical paths for packaged, trusted model artifacts
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "url_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "url_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "url-model-1.0"


class UrlModelManager:
    """Singleton model manager for loading and executing the URL classifier."""

    _instance: Optional["UrlModelManager"] = None

    def __init__(self):
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self.top_important_features: List[tuple] = []
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "UrlModelManager":
        if cls._instance is None:
            cls._instance = UrlModelManager()
        return cls._instance

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        if not MODEL_PATH.exists():
            # Check fallback path in repo root ml/models
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "url_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "url_model_v1_metadata.json"
            else:
                logger.warning(f"URL ML model artifact not found at {MODEL_PATH} or {fallback_path}")
                return
        else:
            target_path = MODEL_PATH
            meta_path = METADATA_PATH

        try:
            logger.info(f"Loading URL ML model pipeline from: {target_path}")
            self.model = joblib.load(target_path)
            logger.info("URL ML model pipeline successfully loaded into memory.")

            if meta_path.exists():
                try:
                    self.metadata = json.loads(meta_path.read_text(encoding="utf-8"))
                    self.model_version = self.metadata.get("model_version", DEFAULT_MODEL_VERSION)
                    importances = self.metadata.get("feature_importances", {})
                    self.top_important_features = sorted(
                        importances.items(), key=lambda x: x[1], reverse=True
                    )[:8]
                except Exception as meta_err:
                    logger.warning(f"Failed to read model metadata: {meta_err}")
        except Exception as e:
            logger.error(f"Failed to load URL ML model artifact: {e}")
            self.model = None

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(
        self,
        url: str,
        extracted_features: Optional[UrlFeatures] = None
    ) -> Dict[str, Any]:
        """
        Execute ML prediction on URL features.
        
        Returns:
            Dict containing:
            - prediction: "malicious" | "benign"
            - model_score: float (calibrated model confidence score)
            - model_probability: float (malicious probability 0.0 - 1.0)
            - model_version: str
            - features_used: int
            - top_contributing_features: list of (feature_name, importance_score)
            - available: bool
        """
        if not self.is_ready():
            logger.warning("ML URL model not loaded; returning offline fallback response.")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "features_used": 0,
                "top_contributing_features": [],
                "available": False,
                "error": "ML model artifact not loaded",
            }

        try:
            # 1. Format features strictly into DataFrame matching training schema
            df_features = preprocess_url_for_inference(url, extracted_features)

            # 2. Pipeline inference (preprocessing scaler + classifier)
            preds = self.model.predict(df_features)
            probas = self.model.predict_proba(df_features)[0]

            predicted_class = int(preds[0])
            malicious_prob = float(probas[1])
            benign_prob = float(probas[0])

            label = "malicious" if predicted_class == 1 else "benign"
            score = round(malicious_prob if predicted_class == 1 else benign_prob, 4)

            # 3. Extract top contributing features present in this sample
            contributing = []
            row_dict = df_features.iloc[0].to_dict()
            for feat_name, imp in self.top_important_features:
                val = row_dict.get(feat_name, 0)
                if val != 0:
                    contributing.append({
                        "feature": feat_name,
                        "value": val,
                        "global_importance": imp,
                    })

            return {
                "prediction": label,
                "model_score": score,
                "model_probability": round(malicious_prob, 4),
                "model_version": self.model_version,
                "features_used": len(df_features.columns),
                "top_contributing_features": contributing,
                "available": True,
            }
        except Exception as e:
            logger.error(f"Inference error during predict(): {e}")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "features_used": 0,
                "top_contributing_features": [],
                "available": False,
                "error": str(e),
            }


# Module-level convenience functions
def get_model_manager() -> UrlModelManager:
    return UrlModelManager.get_instance()


def predict_url_threat(
    url: str,
    extracted_features: Optional[UrlFeatures] = None
) -> Dict[str, Any]:
    """Execute URL ML inference using the singleton model manager."""
    return get_model_manager().predict(url, extracted_features)
