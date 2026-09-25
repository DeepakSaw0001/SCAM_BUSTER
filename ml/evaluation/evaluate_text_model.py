"""
ScamBuster ML — Evaluate Text Model

Load the saved text classifier and vectorizer, run predictions on the
held-out test split, and print / save evaluation metrics.

Can also be used to evaluate on new labelled data.

Usage:
    python -m evaluation.evaluate_text_model     (from ml/ directory)
"""

import sys
from pathlib import Path

import pandas as pd
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.text_preprocessor import clean_text
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
    """Re-evaluate the saved text model on the test split."""
    # Load processed dataset
    csv_path = DATASETS_PROCESSED / "sms_spam_clean.csv"
    if not csv_path.exists():
        print("[✗] Processed dataset not found. Run training first:")
        print("    python -m training.train_text_model")
        sys.exit(1)

    df = pd.read_csv(csv_path)

    X = df["clean_message"]
    y = df["label_enc"]

    # Reproduce the same split
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # Load artifacts
    clf = load_artifact("text_classifier.joblib")
    vectorizer = load_artifact("text_vectorizer.joblib")

    # Predict
    X_test_vec = vectorizer.transform(X_test)
    y_pred = clf.predict(X_test_vec)

    # Evaluate
    metrics = full_evaluation(
        y_test, y_pred, labels=[0, 1], target_names=["ham", "spam"]
    )
    print_evaluation(metrics, model_name="TF-IDF + Logistic Regression (SMS Spam)")

    # Also show some example predictions
    y_proba = clf.predict_proba(X_test_vec)
    print("  Sample predictions (first 5 test messages):")
    for i in range(min(5, len(X_test))):
        idx = X_test.index[i]
        label = "spam" if y_pred[i] == 1 else "ham"
        conf = y_proba[i][y_pred[i]]
        print(f"    [{label} p={conf:.3f}] {df.iloc[idx]['message'][:80]}...")

    # Save report
    report = {
        "model": "TF-IDF + Logistic Regression",
        "task": "SMS Spam Classification (re-evaluation)",
        "test_samples": len(X_test),
        "metrics": metrics,
    }
    save_report(report, "text_model_eval.json")

    return metrics


if __name__ == "__main__":
    evaluate()
