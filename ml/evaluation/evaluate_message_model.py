"""
ScamBuster ML — Message Model Evaluation Script (Phase 04)

Loads the trained message_model_v1.joblib pipeline and evaluates it on test data,
printing the confusion matrix and classification metrics.
"""

import json
import sys
from pathlib import Path
import joblib
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

ROOT_DIR = Path(__file__).resolve().parents[2]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

MODEL_PATH = ROOT_DIR / "ml" / "models" / "message_model_v1.joblib"
METADATA_PATH = ROOT_DIR / "ml" / "models" / "message_model_v1_metadata.json"
DATASET_PATH = ROOT_DIR / "ml" / "datasets" / "processed" / "sms_spam_clean.csv"


def run_evaluation():
    print(f"[INFO] Loading model artifact: {MODEL_PATH}")
    pipeline = joblib.load(MODEL_PATH)

    print(f"[INFO] Loading dataset: {DATASET_PATH}")
    df = pd.read_csv(DATASET_PATH)

    # Use test partition with RANDOM_STATE = 42
    from sklearn.model_selection import train_test_split
    X = df["clean_message"].fillna("")
    y = df["label_enc"]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=42, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp
    )

    preds = pipeline.predict(X_test)
    probas = pipeline.predict_proba(X_test)[:, 1]

    cm = confusion_matrix(y_test, preds)
    tn, fp, fn, tp = cm.ravel()

    print("\n" + "=" * 60)
    print("SCAMBUSTER MESSAGE CLASSIFIER EVALUATION REPORT")
    print("=" * 60)
    print(classification_report(y_test, preds, target_names=["Ham / Legitimate", "Spam / Scam"], digits=4))
    print(f"Confusion Matrix:\n  True Negatives (TN):  {tn}\n  False Positives (FP): {fp}\n  False Negatives (FN): {fn}\n  True Positives (TP):  {tp}")
    print("=" * 60)


if __name__ == "__main__":
    run_evaluation()
