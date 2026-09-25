"""
ScamBuster ML — Model Utilities

Shared helpers for loading/saving models and vectorizers,
resolving paths, and printing evaluation reports.
"""

import os
import json
from pathlib import Path
from datetime import datetime, timezone

import joblib
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

# ── paths ────────────────────────────────────────────────────────────────
ML_ROOT = Path(__file__).resolve().parent.parent          # ml/
MODELS_DIR = ML_ROOT / "models"
DATASETS_RAW = ML_ROOT / "datasets" / "raw"
DATASETS_PROCESSED = ML_ROOT / "datasets" / "processed"
REPORTS_DIR = ML_ROOT / "evaluation" / "reports"

for _d in (MODELS_DIR, DATASETS_RAW, DATASETS_PROCESSED, REPORTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


# ── model persistence ───────────────────────────────────────────────────
def save_artifact(obj, filename: str) -> Path:
    """Save a sklearn model / vectorizer to ml/models/<filename>."""
    path = MODELS_DIR / filename
    joblib.dump(obj, path)
    print(f"[OK] Saved artifact -> {path}")
    return path


def load_artifact(filename: str):
    """Load a sklearn model / vectorizer from ml/models/<filename>."""
    path = MODELS_DIR / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Model artifact not found: {path}. Run the training script first."
        )
    return joblib.load(path)


# ── evaluation ───────────────────────────────────────────────────────────
def full_evaluation(y_true, y_pred, labels=None, target_names=None):
    """Return a dict with accuracy, precision, recall, F1, confusion matrix."""
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, average="binary" if len(set(y_true)) == 2 else "weighted", pos_label=labels[1] if labels else 1)),
        "recall": float(recall_score(y_true, y_pred, average="binary" if len(set(y_true)) == 2 else "weighted", pos_label=labels[1] if labels else 1)),
        "f1_score": float(f1_score(y_true, y_pred, average="binary" if len(set(y_true)) == 2 else "weighted", pos_label=labels[1] if labels else 1)),
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        "classification_report": classification_report(
            y_true, y_pred, labels=labels, target_names=target_names, output_dict=True
        ),
    }


def print_evaluation(metrics: dict, model_name: str = "Model"):
    """Pretty-print evaluation metrics to the console."""
    print(f"\n{'=' * 60}")
    print(f"  Evaluation -- {model_name}")
    print(f"{'=' * 60}")
    print(f"  Accuracy  : {metrics['accuracy']:.4f}")
    print(f"  Precision : {metrics['precision']:.4f}")
    print(f"  Recall    : {metrics['recall']:.4f}")
    print(f"  F1 Score  : {metrics['f1_score']:.4f}")
    print(f"\n  Confusion Matrix:")
    for row in metrics["confusion_matrix"]:
        print(f"    {row}")
    print(f"{'=' * 60}\n")


def save_report(report: dict, filename: str) -> Path:
    """Save an evaluation report as JSON to ml/evaluation/reports/."""
    path = REPORTS_DIR / filename
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"[OK] Report saved -> {path}")
    return path
