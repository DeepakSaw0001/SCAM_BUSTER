"""
ScamBuster ML — Android APK Malware Detection Model Training & Evaluation Pipeline (Phase 07)

Trains and evaluates classical machine learning models on static APK features:
- Model 1: StandardScaler + Logistic Regression (L2 regularization, balanced weights)
- Model 2: StandardScaler + Random Forest Classifier (100 trees, max depth 12, balanced weights)

Safeguards:
- 80% Train / 20% Test stratified split (RANDOM_STATE = 42)
- Zero data leakage: scalers and estimators fitted strictly on training partition
- Real metric evaluation: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix
- Model persistence to ml/models/apk_model_v1.joblib and backend/app/ml/models/
"""

import json
import logging
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

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ML_DIR = ROOT_DIR / "ml"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from ml.features.apk_features import APK_FEATURE_NAMES, APK_FEATURE_VERSION

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("train_apk_model")

DATASET_PATH = ML_DIR / "datasets" / "processed" / "apk_corpus_clean.csv"
MODEL_OUTPUT_PATH = ML_DIR / "models" / "apk_model_v1.joblib"
METADATA_OUTPUT_PATH = ML_DIR / "models" / "apk_model_v1_metadata.json"
BACKEND_MODEL_DIR = BACKEND_DIR / "app" / "ml" / "models"


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
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Clean APK dataset not found at {DATASET_PATH}. Run prepare_apk_dataset.py first.")

    df = pd.read_csv(DATASET_PATH)
    logger.info("Loaded %d rows from %s", len(df), DATASET_PATH)

    X = df[APK_FEATURE_NAMES].values.astype(np.float32)
    y = df["label"].values.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    logger.info("Train split: %d, Test split: %d", len(y_train), len(y_test))

    # Model 1: Logistic Regression
    lr_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(class_weight="balanced", random_state=42, max_iter=1000))
    ])
    logger.info("Training Model 1: Logistic Regression...")
    lr_pipe.fit(X_train, y_train)
    lr_metrics = evaluate_model("Logistic_Regression", lr_pipe, X_test, y_test)

    # Model 2: Random Forest Classifier
    rf_pipe = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", RandomForestClassifier(n_estimators=100, max_depth=12, class_weight="balanced", random_state=42))
    ])
    logger.info("Training Model 2: Random Forest...")
    rf_pipe.fit(X_train, y_train)
    rf_metrics = evaluate_model("Random_Forest", rf_pipe, X_test, y_test)

    # Selection
    candidates = [
        ("Logistic_Regression", lr_pipe, lr_metrics),
        ("Random_Forest", rf_pipe, rf_metrics),
    ]
    candidates.sort(key=lambda c: (c[2]["f1_score"], c[2]["roc_auc"]), reverse=True)
    best_name, best_pipeline, best_metrics = candidates[0]
    logger.info("Selected model: %s with F1: %.4f, AUC: %.4f", best_name, best_metrics["f1_score"], best_metrics["roc_auc"])

    # Feature importances if tree model
    feature_importances = []
    clf = best_pipeline.named_steps["classifier"]
    if hasattr(clf, "feature_importances_"):
        for name, imp in zip(APK_FEATURE_NAMES, clf.feature_importances_):
            feature_importances.append({"feature": name, "importance": round(float(imp), 4)})
        feature_importances.sort(key=lambda x: x["importance"], reverse=True)

    # Save artifact
    MODEL_OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    artifact = {
        "pipeline": best_pipeline,
        "feature_names": APK_FEATURE_NAMES,
        "feature_version": APK_FEATURE_VERSION,
        "model_name": best_name,
        "version": "apk_model_v1.0",
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, MODEL_OUTPUT_PATH)
    logger.info("Saved APK model artifact to %s", MODEL_OUTPUT_PATH)

    metadata = {
        "model_name": "apk_classifier",
        "version": "1.0",
        "algorithm": best_name,
        "feature_version": APK_FEATURE_VERSION,
        "features": APK_FEATURE_NAMES,
        "training_dataset": "apk_corpus_clean.csv",
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
        "top_features": feature_importances[:10] if feature_importances else [],
    }
    with open(METADATA_OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    logger.info("Saved metadata to %s", METADATA_OUTPUT_PATH)

    # Sync to backend
    BACKEND_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    backend_artifact = BACKEND_MODEL_DIR / "apk_model_v1.joblib"
    backend_meta = BACKEND_MODEL_DIR / "apk_model_v1_metadata.json"
    shutil.copy2(MODEL_OUTPUT_PATH, backend_artifact)
    shutil.copy2(METADATA_OUTPUT_PATH, backend_meta)
    logger.info("Synchronized model to backend %s", backend_artifact)


if __name__ == "__main__":
    train_and_evaluate()
