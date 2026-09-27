"""
ScamBuster ML Message Inference Service (Phase 04)

Thread-safe, singleton inference service for SMS / Text Scam detection.
Loads the trusted packaged TF-IDF + Calibrated LinearSVC pipeline once and serves
fast, stateless predictions.

Privacy & Security:
- Does NOT log raw message content.
- Evaluates purely offline, local model (zero external LLM / cloud dependencies).
- Fails safely with structured offline fallbacks if the artifact is missing or corrupted.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

import joblib

from app.services.message_preprocessor import (
    PreprocessedMessage,
    preprocess_message,
)

logger = logging.getLogger("scambuster.message_inference")

# Canonical paths for packaged model artifacts
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "message_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "message_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "message-model-1.0"


class MessageModelManager:
    """Singleton manager for loading and executing the SMS/Message classifier pipeline."""

    _instance: Optional["MessageModelManager"] = None

    def __init__(self):
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "MessageModelManager":
        if cls._instance is None:
            cls._instance = MessageModelManager()
        return cls._instance

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        if not MODEL_PATH.exists():
            # Check fallback path in repo root ml/models
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "message_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "message_model_v1_metadata.json"
            else:
                logger.warning(f"Message ML model artifact not found at {MODEL_PATH} or {fallback_path}")
                return
        else:
            target_path = MODEL_PATH
            meta_path = METADATA_PATH

        try:
            logger.info(f"Loading Message ML model pipeline from: {target_path}")
            self.model = joblib.load(target_path)
            logger.info("Message ML model pipeline successfully loaded into memory.")

            if meta_path.exists():
                try:
                    self.metadata = json.loads(meta_path.read_text(encoding="utf-8"))
                    self.model_version = self.metadata.get("model_version", DEFAULT_MODEL_VERSION)
                except Exception as meta_err:
                    logger.warning(f"Failed to read message model metadata: {meta_err}")
        except Exception as e:
            logger.error(f"Failed to load Message ML model artifact: {e}")
            self.model = None

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(
        self,
        message: str,
        preprocessed: Optional[PreprocessedMessage] = None,
    ) -> Dict[str, Any]:
        """
        Execute NLP prediction on message text.

        Returns:
            Dict containing:
            - prediction: "scam" | "legitimate"
            - model_score: float (probability of predicted class)
            - model_probability: float (probability of scam class 0.0 - 1.0)
            - model_version: str
            - available: bool
            - clean_tokens_count: int
        """
        if not self.is_ready():
            logger.warning("Message ML model not loaded; returning safe fallback.")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "available": False,
                "clean_tokens_count": 0,
                "error": "Message ML model artifact not loaded",
            }

        try:
            if preprocessed is None:
                preprocessed = preprocess_message(message)

            cleaned_text = preprocessed.cleaned_text
            if not cleaned_text:
                # Empty message after cleaning
                return {
                    "prediction": "legitimate",
                    "model_score": 0.50,
                    "model_probability": 0.0,
                    "model_version": self.model_version,
                    "available": True,
                    "clean_tokens_count": 0,
                }

            # Predict via TF-IDF + Classifier pipeline
            preds = self.model.predict([cleaned_text])
            probas = self.model.predict_proba([cleaned_text])[0]

            predicted_class = int(preds[0])
            spam_prob = float(probas[1])
            ham_prob = float(probas[0])

            label = "scam" if predicted_class == 1 else "legitimate"
            score = round(spam_prob if predicted_class == 1 else ham_prob, 4)

            return {
                "prediction": label,
                "model_score": score,
                "model_probability": round(spam_prob, 4),
                "model_version": self.model_version,
                "available": True,
                "clean_tokens_count": len(cleaned_text.split()),
            }
        except Exception as e:
            logger.error(f"Inference error during message predict(): {e}")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "available": False,
                "clean_tokens_count": 0,
                "error": str(e),
            }


# Module-level convenience functions
def get_message_model_manager() -> MessageModelManager:
    return MessageModelManager.get_instance()


def predict_message_threat(
    message: str,
    preprocessed: Optional[PreprocessedMessage] = None,
) -> Dict[str, Any]:
    """Execute SMS/Message ML inference using the singleton model manager."""
    return get_message_model_manager().predict(message, preprocessed)
