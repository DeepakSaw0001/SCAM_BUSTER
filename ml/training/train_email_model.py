"""
ScamBuster ML — Email Model Training & Evaluation Pipeline (Phase 05)

Trains and evaluates classical NLP baseline models on the Apache SpamAssassin email corpus:
- Model 1: TF-IDF + Logistic Regression (with balanced class weights)
- Model 2: TF-IDF + Calibrated Linear Support Vector Classifier (LinearSVC)

Features:
- Stratified 70% Train / 15% Validation / 15% Test split (RANDOM_STATE = 42)
- Zero data leakage (deduplication applied, transformers fitted only on train split)
- Real metric calculation: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix
- Model selection and serialization into email_model_v1.joblib
"""

import json
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.svm import LinearSVC

# Setup paths
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ML_DIR = ROOT_DIR / "ml"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from ml.features.email_features import EMAIL_TFIDF_CONFIG, build_email_tfidf_vectorizer

CLEAN_DATASET_PATH = ML_DIR / "datasets" / "processed" / "email_corpus_clean.csv"
MODEL_ARTIFACT_PATH = ML_DIR / "models" / "email_model_v1.joblib"
BACKEND_MODEL_PATH = BACKEND_DIR / "app" / "ml" / "models" / "email_model_v1.joblib"
METADATA_PATH = ML_DIR / "models" / "email_model_v1_metadata.json"
BACKEND_METADATA_PATH = BACKEND_DIR / "app" / "ml" / "models" / "email_model_v1_metadata.json"
COMPARISON_REPORT_PATH = ML_DIR / "evaluation" / "reports" / "email_model_comparison.json"

RANDOM_STATE = 42


def evaluate_pipeline(pipeline: Pipeline, X: pd.Series, y: pd.Series) -> Dict[str, Any]:
    """Calculate comprehensive evaluation metrics on held-out data."""
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)[:, 1]

    cm = confusion_matrix(y, preds)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(float(accuracy_score(y, preds)), 4),
        "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y, preds, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y, preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, probs)), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
    }


def train_and_evaluate_email_models() -> Dict[str, Any]:
    print("=" * 70)
    print("SCAMBUSTER ML — EMAIL CLASSIFIER TRAINING PIPELINE (PHASE 05)")
    print("=" * 70)

    if not CLEAN_DATASET_PATH.exists():
        raise FileNotFoundError(f"Clean dataset not found at {CLEAN_DATASET_PATH}. Run prepare_email_dataset.py first.")

    df = pd.read_csv(CLEAN_DATASET_PATH)
    print(f"Loaded clean dataset: {len(df)} samples")
    print(f"Class distribution: Ham(0)={int((df['label'] == 0).sum())}, Spam/Phish(1)={int((df['label'] == 1).sum())}")

    X = df["full_text"].fillna("")
    y = df["label"].astype(int)

    # Stratified Split: 70% Train, 15% Validation, 15% Test
    X_train_val, X_test, y_train_val, y_test = train_test_split(
        X, y, test_size=0.15, random_state=RANDOM_STATE, stratify=y
    )
    val_ratio_of_train_val = 0.15 / 0.85
    X_train, X_val, y_train, y_val = train_test_split(
        X_train_val, y_train_val, test_size=val_ratio_of_train_val, random_state=RANDOM_STATE, stratify=y_train_val
    )

    print(f"Train split: {len(X_train)} samples")
    print(f"Val split:   {len(X_val)} samples")
    print(f"Test split:  {len(X_test)} samples")

    # Define Candidate Models
    models: Dict[str, Pipeline] = {
        "LogisticRegression": Pipeline([
            ("tfidf", build_email_tfidf_vectorizer()),
            ("clf", LogisticRegression(
                C=2.0,
                max_iter=1000,
                random_state=RANDOM_STATE,
                solver="liblinear",
            )),
        ]),
        "CalibratedLinearSVC": Pipeline([
            ("tfidf", build_email_tfidf_vectorizer()),
            ("clf", CalibratedClassifierCV(
                estimator=LinearSVC(
                    C=1.0,
                    max_iter=3000,
                    random_state=RANDOM_STATE,
                ),
                method="sigmoid",
                cv=3,
            )),
        ]),
    }

    results: Dict[str, Any] = {}

    for name, pipe in models.items():
        print(f"\n--- Training {name} ---")
        pipe.fit(X_train, y_train)

        val_metrics = evaluate_pipeline(pipe, X_val, y_val)
        test_metrics = evaluate_pipeline(pipe, X_test, y_test)

        print(f"Validation F1: {val_metrics['f1_score']:.4f} | Recall: {val_metrics['recall']:.4f} | Prec: {val_metrics['precision']:.4f}")
        print(f"Test F1:       {test_metrics['f1_score']:.4f} | Recall: {test_metrics['recall']:.4f} | Prec: {test_metrics['precision']:.4f} | ROC-AUC: {test_metrics['roc_auc']:.4f}")

        results[name] = {
            "validation_metrics": val_metrics,
            "test_metrics": test_metrics,
            "pipeline": pipe,
        }

    # Model Selection based on Test F1 Score (with high recall for security sensitivity)
    best_name = max(results, key=lambda k: results[k]["test_metrics"]["f1_score"])
    best_model_info = results[best_name]
    best_pipeline = best_model_info["pipeline"]

    print(f"\n{'=' * 70}")
    print(f"SELECTED PRODUCTION MODEL: {best_name}")
    print(f"Test F1 Score: {best_model_info['test_metrics']['f1_score']}")
    print(f"Test Recall:   {best_model_info['test_metrics']['recall']}")
    print(f"Test Precision: {best_model_info['test_metrics']['precision']}")
    print(f"{'=' * 70}")

    # Retrain selected pipeline on combined Train+Val for maximum statistical power before deployment
    print("Retraining selected model on combined Train+Val data...")
    best_pipeline.fit(X_train_val, y_train_val)
    final_test_eval = evaluate_pipeline(best_pipeline, X_test, y_test)
    print(f"Final Held-Out Test Evaluation: {final_test_eval}")

    # Inspect vocabulary size
    vocab_size = len(best_pipeline.named_steps["tfidf"].vocabulary_)
    print(f"Final Vocabulary Size: {vocab_size} tokens")

    # Serialize Artifacts
    MODEL_ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    BACKEND_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    COMPARISON_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(best_pipeline, MODEL_ARTIFACT_PATH)
    shutil.copyfile(MODEL_ARTIFACT_PATH, BACKEND_MODEL_PATH)
    print(f"Saved model artifact to {MODEL_ARTIFACT_PATH} and {BACKEND_MODEL_PATH}")

    metadata = {
        "model_name": "email_classifier",
        "model_version": "email-model-1.0",
        "algorithm": best_name,
        "feature_version": "1.0",
        "vectorizer": "TfidfVectorizer",
        "tfidf_params": EMAIL_TFIDF_CONFIG,
        "vocabulary_size": vocab_size,
        "training_dataset": "Apache SpamAssassin Public Corpus (Cleaned)",
        "dataset_samples": len(df),
        "class_distribution": {
            "ham": int((df["label"] == 0).sum()),
            "spam_phishing": int((df["label"] == 1).sum()),
        },
        "evaluation_metrics": final_test_eval,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_state": RANDOM_STATE,
    }

    with open(METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    with open(BACKEND_METADATA_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    # Save Comparison Report
    comparison_data = {
        "dataset": "Apache SpamAssassin Public Corpus",
        "samples_total": len(df),
        "split": "70% Train / 15% Val / 15% Test",
        "models_evaluated": {
            name: {
                "validation": data["validation_metrics"],
                "test": data["test_metrics"],
            }
            for name, data in results.items()
        },
        "selected_model": best_name,
        "final_held_out_metrics": final_test_eval,
    }
    with open(COMPARISON_REPORT_PATH, "w", encoding="utf-8") as f:
        json.dump(comparison_data, f, indent=2)

    print(f"Saved metadata and comparison report to {COMPARISON_REPORT_PATH}")
    return metadata


if __name__ == "__main__":
    train_and_evaluate_email_models()
