"""
ScamBuster ML — Evaluate URL Model

Load the saved URL classifier, run predictions on the held-out test
split, and print / save evaluation metrics.

Usage:
    python -m evaluation.evaluate_url_model      (from ml/ directory)
"""

import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.url_features import FEATURE_NAMES
from utils.model_utils import (
    DATASETS_PROCESSED,
    load_artifact,
    full_evaluation,
    print_evaluation,
    save_report,
)

RANDOM_STATE = 42
TEST_SIZE = 0.20


def evaluate():
    """Re-evaluate the saved URL model on the test split."""
    csv_path = DATASETS_PROCESSED / "url_features_clean.csv"
    if not csv_path.exists():
        print("[ERROR] Processed dataset not found. Run training first:")
        print("    python -m training.train_url_model")
        sys.exit(1)

    df = pd.read_csv(csv_path)
    X = df[FEATURE_NAMES].values
    y = df["label"].values

    # Reproduce the same split
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # Load model
    clf = load_artifact("url_classifier.joblib")

    # Predict
    y_pred = clf.predict(X_test)

    # Evaluate
    metrics = full_evaluation(
        y_test, y_pred, labels=[0, 1], target_names=["benign", "malicious"]
    )
    print_evaluation(metrics, model_name="URL Features + Random Forest (Phishing)")

    # Sample predictions
    y_proba = clf.predict_proba(X_test)
    print("  Sample predictions (first 5 test URLs):")
    test_urls = df.iloc[
        df.index[len(df) - len(y_test):][:5]
    ]["url"].values if "url" in df.columns else ["(url not in features file)"] * 5

    for i in range(min(5, len(X_test))):
        label = "malicious" if y_pred[i] == 1 else "benign"
        conf = y_proba[i][y_pred[i]]
        url_display = test_urls[i][:80] if i < len(test_urls) else "N/A"
        print(f"    [{label} p={conf:.3f}] {url_display}")

    # Save report
    report = {
        "model": "URL Features + Random Forest",
        "task": "Phishing URL Classification (re-evaluation)",
        "test_samples": len(X_test),
        "metrics": metrics,
    }
    save_report(report, "url_model_eval.json")

    return metrics


if __name__ == "__main__":
    evaluate()
