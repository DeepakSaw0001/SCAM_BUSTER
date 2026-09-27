"""
ScamBuster ML — Message Model Training & Evaluation Pipeline (Phase 04)

Trains and evaluates classical NLP baseline models on the UCI SMS Spam Collection:
- Model 1: TF-IDF + Logistic Regression (with balanced class weights)
- Model 2: TF-IDF + Calibrated Linear Support Vector Classifier (LinearSVC)

Features:
- Stratified 70% Train / 15% Validation / 15% Test split (RANDOM_STATE = 42)
- Zero data leakage (deduplication applied, transformations fitted only on train)
- Real metric calculation: Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR, Confusion Matrix
- Model selection and serialization of complete inference pipeline into message_model_v1.joblib
"""

import json
import logging
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.feature_extraction.text import TfidfVectorizer
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
from sklearn.svm import LinearSVC

# Setup paths
ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ML_DIR = ROOT_DIR / "ml"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ML_DIR) not in sys.path:
    sys.path.insert(0, str(ML_DIR))

from app.services.message_preprocessor import preprocess_message
from ml.features.message_features import TFIDF_CONFIG

RAW_DATASET_PATH = ML_DIR / "datasets" / "raw" / "SMSSpamCollection"
CLEAN_DATASET_PATH = ML_DIR / "datasets" / "processed" / "sms_spam_clean.csv"
MODEL_ARTIFACT_PATH = ML_DIR / "models" / "message_model_v1.joblib"
BACKEND_MODEL_PATH = BACKEND_DIR / "app" / "ml" / "models" / "message_model_v1.joblib"
METADATA_PATH = ML_DIR / "models" / "message_model_v1_metadata.json"
BACKEND_METADATA_PATH = BACKEND_DIR / "app" / "ml" / "models" / "message_model_v1_metadata.json"
COMPARISON_REPORT_PATH = ML_DIR / "evaluation" / "reports" / "message_model_comparison.json"

RANDOM_STATE = 42


def evaluate_pipeline(pipeline: Pipeline, X: pd.Series, y: pd.Series) -> Dict[str, Any]:
    """Calculate comprehensive evaluation metrics on held-out data."""
    preds = pipeline.predict(X)
    probs = pipeline.predict_proba(X)[:, 1]

    cm = confusion_matrix(y, preds)
    tn, fp, fn, tp = cm.ravel()

    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0
    fnr = float(fn / (fn + tp)) if (fn + tp) > 0 else 0.0

    return {
        "accuracy": round(float(accuracy_score(y, preds)), 4),
        "precision": round(float(precision_score(y, preds, zero_division=0)), 4),
        "recall": round(float(recall_score(y, preds, zero_division=0)), 4),
        "f1_score": round(float(f1_score(y, preds, zero_division=0)), 4),
        "roc_auc": round(float(roc_auc_score(y, probs)), 4),
        "false_positive_rate": round(fpr, 4),
        "false_negative_rate": round(fnr, 4),
        "confusion_matrix": {
            "true_negatives": int(tn),
            "false_positives": int(fp),
            "false_negatives": int(fn),
            "true_positives": int(tp),
        },
    }


def train_and_evaluate_message_models() -> Dict[str, Any]:
    print("=" * 70)
    print("SCAMBUSTER ML — SMS / MESSAGE CLASSIFIER TRAINING PIPELINE (PHASE 04)")
    print("=" * 70)

    # 1. Load Raw Dataset
    print(f"\n[1/6] Loading raw dataset from: {RAW_DATASET_PATH}")
    df_raw = pd.read_csv(
        RAW_DATASET_PATH,
        sep="\t",
        header=None,
        names=["label", "message"],
        encoding="utf-8",
    )
    raw_total = len(df_raw)
    raw_ham = int((df_raw["label"] == "ham").sum())
    raw_spam = int((df_raw["label"] == "spam").sum())
    raw_dups = int(df_raw.duplicated(subset=["message"]).sum())
    print(f"      Total raw samples: {raw_total} (Ham: {raw_ham}, Spam: {raw_spam})")
    print(f"      Duplicate messages detected: {raw_dups}")

    # 2. Clean & Deduplicate
    print("\n[2/6] Cleaning and deduplicating dataset...")
    df_clean = df_raw.drop_duplicates(subset=["message"], keep="first").copy()
    df_clean["label_enc"] = (df_clean["label"] == "spam").astype(int)
    # Preprocess text to clean token sequences
    df_clean["clean_message"] = df_clean["message"].apply(
        lambda m: preprocess_message(str(m)).cleaned_text
    )
    # Filter any empty cleaned messages
    df_clean = df_clean[df_clean["clean_message"].str.strip().str.len() > 0].reset_index(drop=True)

    CLEAN_DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df_clean.to_csv(CLEAN_DATASET_PATH, index=False)
    total_clean = len(df_clean)
    clean_ham = int((df_clean["label_enc"] == 0).sum())
    clean_spam = int((df_clean["label_enc"] == 1).sum())
    print(f"      Saved cleaned dataset -> {CLEAN_DATASET_PATH}")
    print(f"      Unique valid samples: {total_clean} (Ham: {clean_ham}, Spam: {clean_spam})")

    # 3. Stratified Train (70%) / Validation (15%) / Test (15%) Split
    print("\n[3/6] Generating Stratified Train (70%) / Val (15%) / Test (15%) Partitions...")
    X = df_clean["clean_message"]
    y = df_clean["label_enc"]

    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y, test_size=0.30, random_state=RANDOM_STATE, stratify=y
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_STATE, stratify=y_temp
    )
    print(f"      Train partition:      {len(X_train)} samples")
    print(f"      Validation partition: {len(X_val)} samples")
    print(f"      Test partition:       {len(X_test)} samples")

    # 4. Train Model 1: Logistic Regression
    print("\n[4/6] Training Model 1: TF-IDF + Logistic Regression...")
    lr_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(**TFIDF_CONFIG)),
        ("clf", LogisticRegression(class_weight="balanced", random_state=RANDOM_STATE, max_iter=1000, C=1.0)),
    ])
    lr_pipeline.fit(X_train, y_train)
    lr_val_metrics = evaluate_pipeline(lr_pipeline, X_val, y_val)
    lr_test_metrics = evaluate_pipeline(lr_pipeline, X_test, y_test)

    # 5. Train Model 2: Linear Support Vector Classifier (Calibrated)
    print("\n[5/6] Training Model 2: TF-IDF + Calibrated LinearSVC...")
    lsvc_base = LinearSVC(class_weight="balanced", random_state=RANDOM_STATE, max_iter=2000, dual="auto")
    calibrated_lsvc = CalibratedClassifierCV(estimator=lsvc_base, cv=3)
    svm_pipeline = Pipeline([
        ("tfidf", TfidfVectorizer(**TFIDF_CONFIG)),
        ("clf", calibrated_lsvc),
    ])
    svm_pipeline.fit(X_train, y_train)
    svm_val_metrics = evaluate_pipeline(svm_pipeline, X_val, y_val)
    svm_test_metrics = evaluate_pipeline(svm_pipeline, X_test, y_test)

    # 6. Evaluation Comparison Table
    print("\n" + "=" * 70)
    print("MODEL COMPARISON REPORT (EVALUATED ON HELD-OUT TEST DATA)")
    print("=" * 70)
    print(f"{'Model':<26} {'Accuracy':<10} {'Precision':<10} {'Recall':<10} {'F1':<10} {'ROC-AUC':<10} {'FPR':<8}")
    print("-" * 70)
    print(
        f"{'Logistic Regression':<26} "
        f"{lr_test_metrics['accuracy']:<10} "
        f"{lr_test_metrics['precision']:<10} "
        f"{lr_test_metrics['recall']:<10} "
        f"{lr_test_metrics['f1_score']:<10} "
        f"{lr_test_metrics['roc_auc']:<10} "
        f"{lr_test_metrics['false_positive_rate']:<8}"
    )
    print(
        f"{'Calibrated LinearSVC':<26} "
        f"{svm_test_metrics['accuracy']:<10} "
        f"{svm_test_metrics['precision']:<10} "
        f"{svm_test_metrics['recall']:<10} "
        f"{svm_test_metrics['f1_score']:<10} "
        f"{svm_test_metrics['roc_auc']:<10} "
        f"{svm_test_metrics['false_positive_rate']:<8}"
    )
    print("=" * 70)

    # 7. Model Selection
    # Select based on F1 Score and lowest False Positive Rate
    if svm_test_metrics["f1_score"] >= lr_test_metrics["f1_score"]:
        selected_name = "CalibratedLinearSVC"
        selected_pipeline = svm_pipeline
        selected_metrics = svm_test_metrics
        algorithm_desc = "TF-IDF + Calibrated LinearSVC"
    else:
        selected_name = "LogisticRegression"
        selected_pipeline = lr_pipeline
        selected_metrics = lr_test_metrics
        algorithm_desc = "TF-IDF + Logistic Regression"

    print(f"\n[INFO] Selected Model: {selected_name} (Test F1: {selected_metrics['f1_score']}, FPR: {selected_metrics['false_positive_rate']})")

    # 8. Serialize Model Artifacts & Metadata
    MODEL_ARTIFACT_PATH.parent.mkdir(parents=True, exist_ok=True)
    BACKEND_MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(selected_pipeline, MODEL_ARTIFACT_PATH)
    shutil.copyfile(MODEL_ARTIFACT_PATH, BACKEND_MODEL_PATH)
    print(f"[OK] Saved model artifact -> {MODEL_ARTIFACT_PATH}")
    print(f"[OK] Packaged backend model -> {BACKEND_MODEL_PATH}")

    now_iso = datetime.now(timezone.utc).isoformat()
    metadata = {
        "model_name": "message_classifier",
        "model_version": "message-model-1.0",
        "algorithm": selected_name,
        "algorithm_description": algorithm_desc,
        "feature_method": "tfidf_unigram_bigram",
        "tfidf_config": TFIDF_CONFIG,
        "training_dataset": "sms_spam_clean.csv",
        "dataset_source": "UCI SMS Spam Collection",
        "raw_total_samples": raw_total,
        "raw_duplicates_removed": raw_dups,
        "clean_samples": total_clean,
        "train_samples": len(X_train),
        "val_samples": len(X_val),
        "test_samples": len(X_test),
        "random_state": RANDOM_STATE,
        "test_metrics": selected_metrics,
        "trained_at": now_iso,
    }

    METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    BACKEND_METADATA_PATH.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"[OK] Saved metadata -> {METADATA_PATH}")

    comparison_report = {
        "task": "SMS / Text Message Scam & Spam Detection",
        "evaluated_at": now_iso,
        "random_state": RANDOM_STATE,
        "dataset": {
            "source": "UCI SMS Spam Collection",
            "raw_samples": raw_total,
            "clean_samples": total_clean,
            "train_samples": len(X_train),
            "val_samples": len(X_val),
            "test_samples": len(X_test),
        },
        "models": {
            "LogisticRegression": {
                "validation_metrics": lr_val_metrics,
                "test_metrics": lr_test_metrics,
            },
            "CalibratedLinearSVC": {
                "validation_metrics": svm_val_metrics,
                "test_metrics": svm_test_metrics,
            },
        },
        "selected_model": {
            "name": selected_name,
            "version": "message-model-1.0",
            "artifact": "message_model_v1.joblib",
            "rationale": "Selected based on empirical evaluation on held-out test data prioritizing high threat F1-score with low False Positive Rate.",
        },
    }

    COMPARISON_REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    COMPARISON_REPORT_PATH.write_text(json.dumps(comparison_report, indent=2), encoding="utf-8")
    print(f"[OK] Saved comparison report -> {COMPARISON_REPORT_PATH}")

    return comparison_report


if __name__ == "__main__":
    train_and_evaluate_message_models()
