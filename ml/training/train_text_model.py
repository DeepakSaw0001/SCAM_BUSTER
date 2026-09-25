"""
ScamBuster ML — Train Text (SMS Spam) Classifier

Dataset : UCI SMS Spam Collection
Source  : https://archive.ics.uci.edu/ml/machine-learning-databases/00228/smsspamcollection.zip
Licence : CC BY 4.0  (see UCI ML Repository)

Pipeline:
    raw SMS text
        → text cleaning  (preprocessing.text_preprocessor)
        → TF-IDF          (features.text_features)
        → Logistic Regression
        → trained model + vectorizer saved to ml/models/

Usage:
    python -m training.train_text_model          (from ml/ directory)
"""

import io
import sys
import zipfile
from pathlib import Path
from datetime import datetime, timezone

import pandas as pd
import requests
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split

# ── project imports (work when run as  python -m training.train_text_model) ──
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from preprocessing.text_preprocessor import clean_text
from features.text_features import build_tfidf_vectorizer
from utils.model_utils import (
    DATASETS_RAW,
    DATASETS_PROCESSED,
    save_artifact,
    full_evaluation,
    print_evaluation,
    save_report,
)

# ── constants ────────────────────────────────────────────────────────────
DATASET_URL = (
    "https://archive.ics.uci.edu/ml/machine-learning-databases/00228/"
    "smsspamcollection.zip"
)
RAW_ZIP = DATASETS_RAW / "smsspamcollection.zip"
RAW_TSV = DATASETS_RAW / "SMSSpamCollection"
PROCESSED_CSV = DATASETS_PROCESSED / "sms_spam_clean.csv"

TEXT_MODEL_FILE = "text_classifier.joblib"
TEXT_VECTORIZER_FILE = "text_vectorizer.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ── download ─────────────────────────────────────────────────────────────
def download_dataset():
    """Download the UCI SMS Spam Collection zip if not already present."""
    if RAW_TSV.exists():
        print(f"[i] Raw dataset already exists at {RAW_TSV}")
        return

    print(f"[↓] Downloading UCI SMS Spam Collection …")
    resp = requests.get(DATASET_URL, timeout=120)
    resp.raise_for_status()

    RAW_ZIP.parent.mkdir(parents=True, exist_ok=True)
    RAW_ZIP.write_bytes(resp.content)
    print(f"[✓] Saved zip → {RAW_ZIP}")

    # Extract
    with zipfile.ZipFile(RAW_ZIP, "r") as zf:
        zf.extractall(DATASETS_RAW)
    print(f"[✓] Extracted → {DATASETS_RAW}")


# ── load & clean ─────────────────────────────────────────────────────────
def load_and_preprocess() -> pd.DataFrame:
    """Load the raw TSV, clean the text, and cache to CSV."""
    if PROCESSED_CSV.exists():
        print(f"[i] Loading cached processed data → {PROCESSED_CSV}")
        return pd.read_csv(PROCESSED_CSV)

    print("[…] Loading raw dataset and preprocessing …")
    df = pd.read_csv(
        RAW_TSV,
        sep="\t",
        header=None,
        names=["label", "message"],
        encoding="latin-1",
    )

    # Binary encode: ham=0, spam=1
    df["label_enc"] = (df["label"] == "spam").astype(int)
    df["clean_message"] = df["message"].apply(clean_text)

    # Drop empty rows after cleaning
    df = df[df["clean_message"].str.strip().astype(bool)].reset_index(drop=True)

    PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(PROCESSED_CSV, index=False)
    print(f"[✓] Processed data saved → {PROCESSED_CSV}")
    return df


# ── train ────────────────────────────────────────────────────────────────
def train():
    """Full training pipeline: download → preprocess → TF-IDF → LR → save."""
    download_dataset()
    df = load_and_preprocess()

    X = df["clean_message"]
    y = df["label_enc"]

    print(f"\n[i] Dataset size : {len(df)}")
    print(f"    Ham (0)      : {(y == 0).sum()}")
    print(f"    Spam (1)     : {(y == 1).sum()}")

    # Train / test split  (stratified to preserve class ratio)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    print(f"    Train size   : {len(X_train)}")
    print(f"    Test size    : {len(X_test)}")

    # TF-IDF
    vectorizer = build_tfidf_vectorizer()
    X_train_vec = vectorizer.fit_transform(X_train)
    X_test_vec = vectorizer.transform(X_test)

    print(f"    TF-IDF vocab : {len(vectorizer.vocabulary_)} terms")

    # Classifier
    clf = LogisticRegression(
        max_iter=1000,
        solver="lbfgs",
        class_weight="balanced",   # handle class imbalance
        random_state=RANDOM_STATE,
    )
    clf.fit(X_train_vec, y_train)

    # Evaluate
    y_pred = clf.predict(X_test_vec)
    metrics = full_evaluation(
        y_test, y_pred, labels=[0, 1], target_names=["ham", "spam"]
    )
    print_evaluation(metrics, model_name="TF-IDF + Logistic Regression (SMS Spam)")

    # Save artifacts
    save_artifact(clf, TEXT_MODEL_FILE)
    save_artifact(vectorizer, TEXT_VECTORIZER_FILE)

    # Save evaluation report
    report = {
        "model": "TF-IDF + Logistic Regression",
        "task": "SMS Spam Classification",
        "dataset": "UCI SMS Spam Collection",
        "dataset_source": DATASET_URL,
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "test_size_ratio": TEST_SIZE,
        "tfidf_vocab_size": len(vectorizer.vocabulary_),
        "features": "TF-IDF (unigrams + bigrams, max 5000 features)",
        "algorithm": "LogisticRegression (solver=lbfgs, class_weight=balanced)",
        "random_state": RANDOM_STATE,
        "metrics": metrics,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    save_report(report, "text_model_report.json")

    print("[✓] Text model training complete.\n")
    return metrics


# ── entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    train()
