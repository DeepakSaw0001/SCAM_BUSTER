"""
ScamBuster ML Email Inference Service (Phase 05)

Thread-safe, singleton inference service for Email Phishing and Scam classification.
Loads the trusted packaged TF-IDF + Logistic Regression pipeline once and serves
fast, stateless predictions.

Privacy & Security:
- Does NOT log raw email content.
- Evaluates purely offline, local model (zero external LLM / cloud dependencies).
- Fails safely with structured offline fallbacks if the artifact is missing or corrupted.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import joblib
import numpy as np

logger = logging.getLogger("scambuster.email_inference")

# Canonical paths for packaged model artifacts
MODELS_DIR = Path(__file__).resolve().parent / "models"
MODEL_PATH = MODELS_DIR / "email_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "email_model_v1_metadata.json"

DEFAULT_MODEL_VERSION = "email-model-1.0"


class EmailModelManager:
    """Singleton manager for loading and executing the email classifier pipeline."""

    _instance: Optional["EmailModelManager"] = None

    def __init__(self):
        self.model = None
        self.metadata: Dict[str, Any] = {}
        self.model_version: str = DEFAULT_MODEL_VERSION
        self._load_artifact()

    @classmethod
    def get_instance(cls) -> "EmailModelManager":
        if cls._instance is None:
            cls._instance = EmailModelManager()
        return cls._instance

    def _load_artifact(self) -> None:
        """Safely load trusted packaged model pipeline and metadata."""
        if not MODEL_PATH.exists():
            # Check fallback path in repo root ml/models
            fallback_path = Path(__file__).resolve().parents[3] / "ml" / "models" / "email_model_v1.joblib"
            if fallback_path.exists():
                target_path = fallback_path
                meta_path = fallback_path.parent / "email_model_v1_metadata.json"
            else:
                logger.warning(f"Email ML model artifact not found at {MODEL_PATH} or {fallback_path}")
                return
        else:
            target_path = MODEL_PATH
            meta_path = METADATA_PATH

        try:
            logger.info(f"Loading Email ML model pipeline from: {target_path}")
            self.model = joblib.load(target_path)
            logger.info("Email ML model pipeline successfully loaded into memory.")

            if meta_path.exists():
                try:
                    self.metadata = json.loads(meta_path.read_text(encoding="utf-8"))
                    self.model_version = self.metadata.get("model_version", DEFAULT_MODEL_VERSION)
                except Exception as meta_err:
                    logger.warning(f"Failed to read email model metadata: {meta_err}")
        except Exception as e:
            logger.error(f"Failed to load Email ML model artifact: {e}")
            self.model = None

    def is_ready(self) -> bool:
        return self.model is not None

    def predict(
        self,
        subject: str,
        body_text: str,
    ) -> Dict[str, Any]:
        """
        Execute NLP prediction on email text (subject + body).

        Returns:
            Dict containing:
            - prediction: "phishing" | "legitimate"
            - model_score: float (probability of predicted class)
            - model_probability: float (probability of phishing class 0.0 - 1.0)
            - model_version: str
            - available: bool
            - features_used: int
            - top_contributing_features: list of token contributions
        """
        combined_text = f"{subject} {body_text}".strip()

        if not self.is_ready():
            logger.warning("Email model artifact unavailable. Returning safe fallback.")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "available": False,
                "features_used": 0,
                "top_contributing_features": [],
            }

        if len(combined_text) < 5:
            # Not enough text content to classify
            return {
                "prediction": "legitimate",
                "model_score": 0.5,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "available": True,
                "features_used": 0,
                "top_contributing_features": [],
            }

        try:
            # Predict probabilities
            probs = self.model.predict_proba([combined_text])[0]
            phish_prob = float(probs[1])
            legit_prob = float(probs[0])

            is_phishing = phish_prob >= 0.5
            prediction = "phishing" if is_phishing else "legitimate"
            model_score = round(phish_prob if is_phishing else legit_prob, 4)
            model_prob_rounded = round(phish_prob, 4)

            # Extract top contributing n-grams
            top_features = self._explain_prediction(combined_text)

            return {
                "prediction": prediction,
                "model_score": model_score,
                "model_probability": model_prob_rounded,
                "model_version": self.model_version,
                "available": True,
                "features_used": len(self.model.named_steps["tfidf"].vocabulary_),
                "top_contributing_features": top_features,
            }
        except Exception as e:
            logger.error(f"Error during email model inference: {e}")
            return {
                "prediction": "unknown",
                "model_score": 0.0,
                "model_probability": 0.0,
                "model_version": self.model_version,
                "available": False,
                "features_used": 0,
                "top_contributing_features": [],
            }

    def _explain_prediction(self, text: str, top_k: int = 5) -> List[Dict[str, Any]]:
        """Identify top vocabulary terms contributing toward phishing prediction."""
        try:
            tfidf = self.model.named_steps.get("tfidf")
            clf = self.model.named_steps.get("clf")
            if not tfidf or not clf:
                return []

            # Transform input text
            vec = tfidf.transform([text])
            feature_names = tfidf.get_feature_names_out()
            nonzero_indices = vec.indices

            if len(nonzero_indices) == 0:
                return []

            # Retrieve model coefficients
            if hasattr(clf, "coef_"):
                coefs = clf.coef_[0]
            elif hasattr(clf, "calibrated_classifiers_"):
                # CalibratedClassifierCV
                coefs = np.mean([cc.estimator.coef_[0] for cc in clf.calibrated_classifiers_], axis=0)
            else:
                return []

            contributions = []
            for idx in nonzero_indices:
                term = feature_names[idx]
                tfidf_val = vec[0, idx]
                weight = coefs[idx] * tfidf_val
                contributions.append((term, float(weight)))

            # Sort descending by positive phishing weight
            contributions.sort(key=lambda x: x[1], reverse=True)
            top_positive = [
                {"feature": term, "weight": round(weight, 4)}
                for term, weight in contributions[:top_k]
                if weight > 0
            ]
            return top_positive
        except Exception as err:
            logger.debug(f"Unable to extract top contributing features: {err}")
            return []


def predict_email_threat(subject: str, body_text: str) -> Dict[str, Any]:
    """Helper functional wrapper for email threat prediction."""
    return EmailModelManager.get_instance().predict(subject, body_text)
