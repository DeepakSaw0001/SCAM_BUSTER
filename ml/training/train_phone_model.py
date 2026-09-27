"""
ScamBuster ML — Phone Scam Detection Model Training & Evaluation Pipeline (Phase 06)

Trains and evaluates classical machine learning models on static phone features:
- Model 1: StandardScaler + Logistic Regression (L2 regularization, balanced class weights)
- Model 2: StandardScaler + Random Forest Classifier (100 estimators, max depth 10, balanced class weights)

Safeguards:
- 80% Train / 20% Test stratified split (RANDOM_STATE = 42)
- Zero data leakage: scaler and estimators fitted strictly on training split
- Evaluation with real metrics: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix
- Model selection and persistence to ml/models/phone_model_v1.joblib and backend/app/ml/models/
"""

import json
import logging
import os
from pathlib import Path
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
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
from sklearn.preprocessing import StandardScaler

# Ensure root, backend, and ml directories are on sys.path
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ML_DIR = ROOT_DIR / "ml"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from ml.features.phone_features import (
    FEATURE_NAMES,
    extract_phone_feature_vector,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_phone_model")

DATASET_PATH = ML_DIR / "datasets" / "processed" / "phone_corpus_clean.csv"
MODEL_OUTPUT_PATH = ML_DIR / "models" / "phone_model_v1.joblib"
METADATA_OUTPUT_PATH = ML_DIR / "models" / "phone_model_v1_metadata.json"
BACKEND_MODEL_DIR = BACKEND_DIR / "app" / "ml" / "models"


def load_dataset() -> pd.DataFrame:
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Clean dataset not found at {DATASET_PATH}. Run prepare_phone_dataset.py first.")
    df = pd.read_csv(DATASET_PATH)
    logger.info("Loaded %d rows from %s", len(df), DATASET_PATH)
    return df


def extract_features(df: pd.DataFrame) -> np.ndarray:
    logger.info("Extracting %d static phone features for %d records...", len(FEATURE_NAMES), len(df))
    X_list = []
    for _, row in df.iterrows():
        vec = extract_phone_feature_vector(row["phone_number"], default_region=row.get("region", "IN"))
        X_list.append(vec)
    return np.array(X_list, dtype=np.float32)


def evaluate_model(name: str, pipeline: Pipeline, X_test: np.ndarray, y_test: np.ndarray) -> Dict[str, Any]:
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))

    cm = confusion_matrix(y_test, y_pred).tolist()
    tn, fp, fn, tp = cm[0][0], cm[0][1], cm[1][0], cm[1][1]
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    metrics = {
        "model_name": name,
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1_score": round(f1, 4),
        "roc_auc": round(roc_auc, 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": cm,
    }

    logger.info(
        "[%s] Acc: %.4f | Prec: %.4f | Rec: %.4f | F1: %.4f | AUC: %.4f | FPR: %.4f | FNR: %.4f",
        name, acc, prec, rec, f1, roc_auc, fpr, fnr
    )
    return metrics


def train_and_evaluate():
    df = load_dataset()
    X = extract_features(df)
    y = df["label"].values.astype(int)

    # 80/20 Stratified Train-Test Split (deduplication already guaranteed at dataset creation)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info("Train set size: %d, Test set size: %d", len(y_train), len(y_test))

    # Model 1: Logistic Regression Pipeline
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000))
    ])
    logger.info("Training Model 1: Logistic Regression...")
    lr_pipe.fit(X_train, y_train)
    lr_metrics = evaluate_model("Logistic_Regression", lr_pipe, X_test, y_test)

    # Model 2: Random Forest Pipeline
    rf_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, max_depth=10, class_weight="balanced", random_state=42))
    ])
    logger.info("Training Model 2: Random Forest...")
    rf_pipe.fit(X_train, y_train)
    rf_metrics = evaluate_model("Random_Forest", rf_pipe, X_test, y_test)

    # Model selection based on F1-score & ROC-AUC
    candidates = [
        ("Logistic_Regression", lr_pipe, lr_metrics),
        ("Random_Forest", rf_pipe, rf_metrics),
    ]
    candidates.sort(key=lambda c: (c[2]["f1_score"], c[2]["roc_auc"]), reverse=True)
    best_name, best_pipeline, best_metrics = candidates[0]
    logger.info("Selected winning model: %s with F1: %.4f, AUC: %.4f", best_name, best_metrics["f1_score"], best_metrics["roc_auc"])

    # Prepare artifact
    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": best_pipeline,
        "feature_names": FEATURE_NAMES,
        "model_name": best_name,
        "version": "phone_model_v1.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, MODEL_OUTPUT_PATH)
    logger.info("Saved phone model artifact to %s", MODEL_OUTPUT_PATH)

    metadata = {
        "model_name": "phone_classifier",
        "version": "1.0",
        "algorithm": best_name,
        "feature_version": "1.0",
        "features": FEATURE_NAMES,
        "training_dataset": "phone_corpus_clean.csv",
        "sample_count": len(df),
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_state": 42,
        "test_metrics": best_metrics,
        "all_model_evaluations": {
            "Logistic_Regression": lr_metrics,
            "Random_Forest": rf_metrics,
        },
    }
    with open(METADATA_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved metadata to %s", METADATA_OUTPUT_PATH)

    # Copy to backend
    BACKEND_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    backend_artifact = BACKEND_MODEL_DIR / "phone_model_v1.joblib"
    backend_meta = BACKEND_MODEL_DIR / "phone_model_v1_metadata.json"
    shutil.copy2(MODEL_OUTPUT_PATH, backend_artifact)
    shutil.copy2(METADATA_OUTPUT_PATH, backend_meta)
    logger.info("Synchronized model artifact to %s and %s", backend_artifact, backend_meta)


if __name__ == "__main__":
    train_and_evaluate()
