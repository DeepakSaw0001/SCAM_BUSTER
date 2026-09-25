"""
ScamBuster ML — Train URL (Phishing) Classifier

Dataset : Phishing URL dataset (raw URLs with labels)
Sources tried (in order):
    1. GitHub mirror of the "Malicious URLs" dataset
    2. Local CSV fallback at ml/datasets/raw/url_dataset.csv

The script extracts structural features from raw URLs and trains
a Random Forest classifier.

Pipeline:
    raw URL string
        → URL feature extraction  (features.url_features)
        → Random Forest
        → trained model saved to ml/models/

Usage:
    python -m training.train_url_model          (from ml/ directory)
"""

import sys
import csv
import io
from pathlib import Path
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import requests
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

# ── project imports ──────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from features.url_features import extract_url_features, FEATURE_NAMES
from utils.model_utils import (
    DATASETS_RAW,
    DATASETS_PROCESSED,
    save_artifact,
    full_evaluation,
    print_evaluation,
    save_report,
)

# ── constants ────────────────────────────────────────────────────────────
# Primary source: a well-known GitHub-hosted phishing URL dataset
DATASET_URLS = [
    # Sid321axn malicious-urls mirror (commonly used in ML courses)
    "https://raw.githubusercontent.com/incertum/cyber-matrix-ai/master/Malicious-URL-Detection-Deep-Learning/data/url.csv",
]

RAW_CSV = DATASETS_RAW / "url_dataset.csv"
PROCESSED_CSV = DATASETS_PROCESSED / "url_features_clean.csv"

URL_MODEL_FILE = "url_classifier.joblib"
URL_FEATURE_NAMES_FILE = "url_feature_names.joblib"

RANDOM_STATE = 42
TEST_SIZE = 0.20


# ── download ─────────────────────────────────────────────────────────────
def download_dataset() -> pd.DataFrame:
    """
    Try to download a phishing URL dataset from known public sources.
    Falls back to a local file if download fails.
    Returns a DataFrame with columns ['url', 'label'].
    label: 1 = malicious/phishing, 0 = benign/legitimate
    """
    if RAW_CSV.exists():
        print(f"[INFO] Raw dataset already exists at {RAW_CSV}")
        return _load_raw_csv(RAW_CSV)

    # Try each source
    for source_url in DATASET_URLS:
        print(f"[DOWNLOADING] Trying to download from: {source_url}")
        try:
            resp = requests.get(source_url, timeout=120)
            resp.raise_for_status()
            RAW_CSV.parent.mkdir(parents=True, exist_ok=True)
            RAW_CSV.write_bytes(resp.content)
            print(f"[OK] Downloaded -> {RAW_CSV}")
            return _load_raw_csv(RAW_CSV)
        except Exception as e:
            print(f"[ERROR] Failed: {e}")
            continue

    # If no download works, try to generate a dataset from PhishTank + legitimate sources
    print("[!] Could not download a pre-built dataset. Attempting to build one from public sources...")
    return _build_dataset_from_public_lists()


def _load_raw_csv(path: Path) -> pd.DataFrame:
    """
    Load and normalise a URL dataset CSV.
    Handles different column naming conventions.
    """
    # Try reading with different encodings and separators
    for sep in [",", "\t"]:
        for encoding in ["utf-8", "latin-1"]:
            try:
                df = pd.read_csv(path, sep=sep, encoding=encoding, on_bad_lines="skip")
                if len(df.columns) >= 2:
                    break
            except Exception:
                continue
        else:
            continue
        break
    else:
        raise ValueError(f"Could not parse {path}")

    # Normalise column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Map common column name patterns to standard names
    url_col = None
    label_col = None

    for c in df.columns:
        if c in ("url", "urls", "uri", "link"):
            url_col = c
        elif c in ("label", "labels", "class", "type", "status", "result", "phishing"):
            label_col = c

    if url_col is None:
        # Assume first column is URL
        url_col = df.columns[0]
    if label_col is None:
        # Assume last column is label
        label_col = df.columns[-1]

    result = pd.DataFrame({
        "url": df[url_col].astype(str),
        "label_raw": df[label_col],
    })

    # Normalise labels to binary: 1 = malicious/phishing, 0 = benign
    result["label"] = _normalise_labels(result["label_raw"])
    result = result[["url", "label"]].dropna().reset_index(drop=True)

    return result


def _normalise_labels(series: pd.Series) -> pd.Series:
    """Map various label conventions to binary 0/1."""
    s = series.astype(str).str.strip().str.lower()

    mapping = {}
    for val in s.unique():
        if val in ("1", "bad", "malicious", "phishing", "spam", "yes", "true", "suspicious"):
            mapping[val] = 1
        elif val in ("0", "good", "benign", "legitimate", "ham", "no", "false", "safe"):
            mapping[val] = 0
        else:
            # Try numeric
            try:
                v = int(float(val))
                mapping[val] = 1 if v >= 1 else 0
            except (ValueError, TypeError):
                mapping[val] = None  # will be dropped

    return s.map(mapping)


import zipfile

def _build_dataset_from_public_lists() -> pd.DataFrame:
    """
    Build a URL dataset by combining:
      - Known phishing/malicious URLs from OpenPhish community feed + abuse.ch URLhaus
      - Legitimate URLs from the official Tranco top-1M list
    """
    phishing_urls = []
    legit_urls = []

    # ── 1. phishing URLs from OpenPhish community feed ──
    print("[DOWNLOADING] Fetching phishing URLs from OpenPhish community feed...")
    try:
        resp = requests.get("https://openphish.com/feed.txt", timeout=60)
        resp.raise_for_status()
        op_urls = [
            u.strip() for u in resp.text.strip().split("\n")
            if u.strip() and u.strip().startswith("http")
        ]
        phishing_urls.extend(op_urls)
        print(f"[OK] Got {len(op_urls)} phishing URLs from OpenPhish")
    except Exception as e:
        print(f"[ERROR] OpenPhish failed: {e}")

    # ── 2. malicious URLs from URLhaus (abuse.ch) ──
    print("[DOWNLOADING] Fetching malicious URLs from abuse.ch URLhaus...")
    try:
        resp = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", timeout=60)
        resp.raise_for_status()
        reader = csv.reader(io.StringIO(resp.text))
        uh_count = 0
        for row in reader:
            if not row or row[0].startswith("#") or len(row) < 3:
                continue
            url_val = row[2].strip()
            if url_val.startswith("http"):
                phishing_urls.append(url_val)
                uh_count += 1
                if uh_count >= 1500:  # Cap at 1500 for balance
                    break
        print(f"[OK] Got {uh_count} malicious URLs from URLhaus")
    except Exception as e:
        print(f"[ERROR] URLhaus failed: {e}")

    # Deduplicate phishing URLs
    phishing_urls = list(dict.fromkeys(phishing_urls))

    # ── 3. legitimate URLs from Tranco top-1M list ──
    print("[DOWNLOADING] Fetching legitimate URLs from Tranco top-sites list...")
    try:
        resp = requests.get("https://tranco-list.eu/top-1m.csv.zip", timeout=120)
        resp.raise_for_status()
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        csv_filename = zf.namelist()[0]
        content_text = zf.read(csv_filename).decode("utf-8", errors="ignore")
        reader = csv.reader(io.StringIO(content_text))
        for row in reader:
            if len(row) >= 2:
                domain = row[1].strip()
                if domain:
                    legit_urls.append(f"https://{domain}")
            elif len(row) == 1 and row[0].strip():
                legit_urls.append(f"https://{row[0].strip()}")

            if len(legit_urls) >= len(phishing_urls):
                break

        print(f"[OK] Got {len(legit_urls)} legitimate URLs from Tranco")
    except Exception as e:
        print(f"[ERROR] Tranco failed: {e}")

    if len(phishing_urls) < 100 or len(legit_urls) < 100:
        print("\n" + "=" * 60)
        print("  [!] DATASET DOWNLOAD FAILED")
        print("=" * 60)
        print("  Could not obtain enough URLs from public sources.")
        print("  Please manually place a CSV file at:")
        print(f"    {RAW_CSV}")
        print("  With columns: url, label")
        print("  Where label: 1 = phishing, 0 = legitimate")
        print("")
        print("  Recommended dataset:")
        print("    Kaggle 'Malicious URLs dataset' by sid321axn")
        print("    https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset")
        print("=" * 60)
        sys.exit(1)

    # Combine and shuffle
    rows = []
    for u in phishing_urls:
        rows.append({"url": u, "label": 1})
    for u in legit_urls:
        rows.append({"url": u, "label": 0})

    df = pd.DataFrame(rows)
    df = df.sample(frac=1, random_state=RANDOM_STATE).reset_index(drop=True)

    # Save for future runs
    RAW_CSV.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(RAW_CSV, index=False)
    print(f"[OK] Built dataset ({len(df)} URLs) -> {RAW_CSV}")

    return df


# ── feature extraction ───────────────────────────────────────────────────
def extract_features_df(df: pd.DataFrame) -> pd.DataFrame:
    """Extract URL features for every row and return a features DataFrame."""
    print(f"[...] Extracting {len(FEATURE_NAMES)} features from {len(df)} URLs ...")
    records = []
    for url in df["url"]:
        records.append(extract_url_features(url))
    features_df = pd.DataFrame(records, columns=FEATURE_NAMES)
    return features_df


# ── train ────────────────────────────────────────────────────────────────
def train():
    """Full training pipeline: download -> extract features -> RF -> save."""
    df = download_dataset()

    print(f"\n[INFO] Dataset size      : {len(df)}")
    print(f"    Benign (0)        : {(df['label'] == 0).sum()}")
    print(f"    Malicious (1)     : {(df['label'] == 1).sum()}")

    # Extract features
    X_df = extract_features_df(df)
    y = df["label"].values

    # Cache processed features
    processed = pd.concat([X_df, df[["url", "label"]].reset_index(drop=True)], axis=1)
    PROCESSED_CSV.parent.mkdir(parents=True, exist_ok=True)
    processed.to_csv(PROCESSED_CSV, index=False)
    print(f"[OK] Processed features saved -> {PROCESSED_CSV}")

    X = X_df.values

    # Train / test split (stratified)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    print(f"    Train size        : {len(X_train)}")
    print(f"    Test size         : {len(X_test)}")

    # Classifier
    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=20,
        min_samples_split=5,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred = clf.predict(X_test)
    metrics = full_evaluation(
        y_test, y_pred, labels=[0, 1], target_names=["benign", "malicious"]
    )
    print_evaluation(metrics, model_name="URL Features + Random Forest (Phishing)")

    # Feature importances
    importances = dict(zip(FEATURE_NAMES, clf.feature_importances_.tolist()))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print("  Top-5 feature importances:")
    for name, imp in sorted_imp[:5]:
        print(f"    {name:30s} {imp:.4f}")

    # Save artifacts
    save_artifact(clf, URL_MODEL_FILE)
    save_artifact(FEATURE_NAMES, URL_FEATURE_NAMES_FILE)

    # Save evaluation report
    report = {
        "model": "URL Features + Random Forest",
        "task": "Phishing URL Classification",
        "dataset": "Combined public phishing URL sources",
        "total_samples": len(df),
        "train_samples": len(X_train),
        "test_samples": len(X_test),
        "test_size_ratio": TEST_SIZE,
        "num_features": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "feature_importances": importances,
        "algorithm": "RandomForestClassifier (n_estimators=100, max_depth=20, class_weight=balanced)",
        "random_state": RANDOM_STATE,
        "metrics": metrics,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }
    save_report(report, "url_model_report.json")

    print("[OK] URL model training complete.\n")
    return metrics


# ── entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    train()
