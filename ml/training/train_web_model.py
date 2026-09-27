"""
ScamBuster ML — Web Risk Classifier Training & Evaluation (Phase 09)

Trains and evaluates candidate classifiers for web & redirect threat classification:
- Logistic Regression (linear baseline)
- Random Forest Classifier (non-linear ensemble)

Target: target_label ('benign', 'suspicious', 'phishing', 'malicious')
Enforces domain-based GroupShuffleSplit to strictly prevent data leakage across splits.
Outputs real evaluation metrics: Accuracy, Precision, Recall, F1, Confusion Matrix, FPR, FNR, ROC-AUC.
"""

import json
import os
import shutil
import sys
from datetime import datetime, timezone
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler, label_binarize

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from ml.features.web_features import WEB_FEATURE_NAMES, WEB_FEATURE_VERSION

DATASET_PATH = os.path.join(ROOT_DIR, "ml", "datasets", "web", "web_risk_corpus.csv")
MODELS_DIR = os.path.join(ROOT_DIR, "ml", "models")
BACKEND_MODELS_DIR = os.path.join(ROOT_DIR, "backend", "app", "ml", "models")
MODEL_OUT_PATH = os.path.join(MODELS_DIR, "web_risk_model_v1.joblib")
META_OUT_PATH = os.path.join(MODELS_DIR, "web_risk_model_v1_metadata.json")

CLASSES = ["benign", "suspicious", "phishing", "malicious"]


def train_web_risk_model(seed: int = 42):
    print("=" * 70)
    print("ScamBuster Phase 09 — Web Risk & Redirect ML Model Training")
    print("=" * 70)

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(f"Dataset not found at {DATASET_PATH}")

    df = pd.read_csv(DATASET_PATH)
    print(f"Loaded dataset: {len(df)} samples, {len(WEB_FEATURE_NAMES)} features")

    X = df[WEB_FEATURE_NAMES]
    y = df["target_label"]
    groups = df["domain"]

    # Strictly disjoint Domain-Grouped Split (Zero Data Leakage)
    gss = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
    train_idx, test_idx = next(gss.split(X, y, groups=groups))

    X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
    y_train, y_test = y.iloc[train_idx], y.iloc[test_idx]

    # Verify zero domain overlap
    train_domains = set(groups.iloc[train_idx])
    test_domains = set(groups.iloc[test_idx])
    overlap = train_domains.intersection(test_domains)
    print(f"Train samples: {len(X_train)} (unique domains: {len(train_domains)})")
    print(f"Test samples:  {len(X_test)} (unique domains: {len(test_domains)})")
    print(f"Domain overlap between train and test: {len(overlap)} (Must be 0)")
    assert len(overlap) == 0, "Data leakage detected: train and test share domain names!"

    pipe_lr = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", LogisticRegression(max_iter=1000, random_state=seed)),
    ])

    pipe_rf = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(n_estimators=100, max_depth=10, random_state=seed)),
    ])

    candidates = {
        "LogisticRegression": pipe_lr,
        "RandomForest": pipe_rf,
    }

    results = {}
    best_name = None
    best_f1 = -1.0
    best_pipe = None

    # Binarize labels for multi-class ROC-AUC calculation
    y_test_bin = label_binarize(y_test, classes=CLASSES)

    for name, pipe in candidates.items():
        print(f"\n--- Training {name} ---")
        pipe.fit(X_train, y_train)
        y_pred = pipe.predict(X_test)
        y_prob = pipe.predict_proba(X_test)

        acc = float(accuracy_score(y_test, y_pred))
        prec = float(precision_score(y_test, y_pred, average="weighted", zero_division=0))
        rec = float(recall_score(y_test, y_pred, average="weighted", zero_division=0))
        f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
        cm = confusion_matrix(y_test, y_pred, labels=CLASSES).tolist()

        # Multi-class ROC-AUC (One-vs-Rest)
        try:
            auc = float(roc_auc_score(y_test_bin, y_prob, multi_class="ovr", average="weighted"))
        except Exception:
            auc = 0.0

        # Calculate False Positive Rate and False Negative Rate on non-benign detection
        # Binary perspective: Benign vs Threat (suspicious/phishing/malicious)
        y_test_threat = (y_test != "benign").astype(int)
        y_pred_threat = (pd.Series(y_pred) != "benign").astype(int)
        cm_bin = confusion_matrix(y_test_threat, y_pred_threat)
        tn, fp, fn, tp = cm_bin.ravel() if cm_bin.shape == (2, 2) else (0, 0, 0, 0)
        fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
        fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

        print(f"  Accuracy:  {acc:.4f}")
        print(f"  Precision: {prec:.4f}")
        print(f"  Recall:    {rec:.4f}")
        print(f"  F1-Score:  {f1:.4f}")
        print(f"  ROC-AUC:   {auc:.4f}")
        print(f"  False Positive Rate (FPR): {fpr:.4f}")
        print(f"  False Negative Rate (FNR): {fnr:.4f}")
        print(f"  Confusion Matrix ({', '.join(CLASSES)}):")
        print(np.array(cm))

        results[name] = {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1_score": f1,
            "roc_auc": auc,
            "fpr": fpr,
            "fnr": fnr,
            "confusion_matrix": cm,
            "classes": CLASSES,
        }

        if f1 > best_f1:
            best_f1 = f1
            best_name = name
            best_pipe = pipe

    print(f"\nSelected Best Model: {best_name} (F1: {best_f1:.4f})")

    # Save artifacts
    os.makedirs(MODELS_DIR, exist_ok=True)
    os.makedirs(BACKEND_MODELS_DIR, exist_ok=True)

    joblib.dump(best_pipe, MODEL_OUT_PATH)
    shutil.copy(MODEL_OUT_PATH, os.path.join(BACKEND_MODELS_DIR, "web_risk_model_v1.joblib"))

    metadata = {
        "model_name": best_name,
        "model_version": "web_model_v1.0",
        "feature_version": WEB_FEATURE_VERSION,
        "features_used": WEB_FEATURE_NAMES,
        "feature_count": len(WEB_FEATURE_NAMES),
        "classes": CLASSES,
        "selected_metrics": results[best_name],
        "all_candidate_metrics": results,
        "dataset_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "split_strategy": "GroupShuffleSplit (grouped by domain, zero overlap)",
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }

    with open(META_OUT_PATH, "w") as f:
        json.dump(metadata, f, indent=2)

    shutil.copy(META_OUT_PATH, os.path.join(BACKEND_MODELS_DIR, "web_risk_model_v1_metadata.json"))

    print(f"Model saved to {MODEL_OUT_PATH} and synced to backend.")
    print(f"Metadata saved to {META_OUT_PATH}")
    return metadata


if __name__ == "__main__":
    train_web_risk_model()
