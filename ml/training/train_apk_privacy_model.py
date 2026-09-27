"""
ScamBuster ML — Android APK Privacy Model Training & Evaluation (Phase 08)

Trains and evaluates candidate classifiers for Android application privacy-risk tier classification:
- Logistic Regression (multi-class baseline)
- Random Forest Classifier (ensemble)

Target: privacy_risk_tier ('low', 'medium', 'high', 'critical')
Model Artifact: ml/models/apk_privacy_model_v1.joblib
"""

import os
import sys
import json
import shutil
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.features.apk_privacy_features import PRIVACY_FEATURE_NAMES, PRIVACY_FEATURE_VERSION

DATASET_PATH = os.path.join(ROOT_DIR, "ml", "datasets", "processed", "apk_privacy_corpus.csv")
MODELS_DIR = os.path.join(ROOT_DIR, "ml", "models")
BACKEND_MODELS_DIR = os.path.join(ROOT_DIR, "backend", "app", "ml", "models")
MODEL_OUT_PATH = os.path.join(MODELS_DIR, "apk_privacy_model_v1.joblib")
META_OUT_PATH = os.path.join(MODELS_DIR, "apk_privacy_model_v1_metadata.json")


def train_apk_privacy_model(seed: int = 42):
    print("=" * 70)
    print("ScamBuster Phase 08 — Android Privacy Risk Model Training")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded dataset: {len(df)} samples, {len(PRIVACY_FEATURE_NAMES)} features")

    X = df[PRIVACY_FEATURE_NAMES]
    y = df["privacy_risk_tier"]

    # Stratified 80/20 train/test split to prevent leakage
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=seed, stratify=y
    )
    print(f"Train samples: {len(X_train)} | Test samples: {len(X_test)}")

    # Candidate 1: Logistic Regression
    pipe_lr = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, random_state=seed)),
    ])

    # Candidate 2: Random Forest
    pipe_rf = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, max_depth=10, random_state=seed)),
    ])

    models = {
        "LogisticRegression": pipe_lr,
        "RandomForest": pipe_rf,
    }

    results = {}
    best_name = None
    best_f1 = -1.0
    best_pipe = None

    for name, pipe in models.items():
        print(f"\nTraining {name}...")
        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)

        acc = accuracy_score(y_test, y_pred)
        prec = precision_score(y_test, y_pred, average="weighted")
        rec = recall_score(y_test, y_pred, average="weighted")
        f1 = f1_score(y_test, y_pred, average="weighted")
        cm = confusion_matrix(y_test, y_pred, labels=["low", "medium", "high", "critical"])

        print(f"  Accuracy:  {acc:.4f}")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall:    {rec:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        print("  Confusion Matrix (low, medium, high, critical):")
        print(cm)

        results[name] = {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": cm.tolist(),
        }

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_pipe = pipe

    print(f"\nWinning Model: {best_name} (Weighted F1: {best_f1:.4f})")

    # Save artifact
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(BACKEND_MODELS_DIR, exist_ok=True)

    artifact = {
        "pipeline": best_pipe,
        "algorithm": best_name,
        "feature_names": PRIVACY_FEATURE_NAMES,
        "feature_version": PRIVACY_FEATURE_VERSION,
        "version": "apk_privacy_model_v1.0",
        "labels": ["low", "medium", "high", "critical"],
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    joblib.dump(artifact, MODEL_OUT_PATH)
    shutil.copyfile(MODEL_OUT_PATH, os.path.join(BACKEND_MODELS_DIR, "apk_privacy_model_v1.joblib"))

    metadata = {
        "model_name": "apk_privacy_classifier",
        "version": "1.0",
        "algorithm": best_name,
        "feature_version": PRIVACY_FEATURE_VERSION,
        "feature_count": len(PRIVACY_FEATURE_NAMES),
        "target_labels": ["low", "medium", "high", "critical"],
        "training_dataset": "apk_privacy_corpus.csv",
        "sample_count": len(df),
        "test_sample_count": len(X_test),
        "metrics": results[best_name],
        "all_model_comparison": results,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": seed,
    }

    with open(META_OUT_PATH, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    shutil.copyfile(META_OUT_PATH, os.path.join(BACKEND_MODELS_DIR, "apk_privacy_model_v1_metadata.json"))

    print(f"Artifact successfully saved to {MODEL_OUT_PATH} and synced to {BACKEND_MODELS_DIR}")
    return metadata


if __name__ == "__main__":
    train_apk_privacy_model()
