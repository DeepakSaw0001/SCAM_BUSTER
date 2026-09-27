# ScamBuster ML — URL Classifier Training Pipeline

This directory contains the reproducible training pipeline for ScamBuster's URL Machine Learning Classifier (Phase 03).

---

## 1. Overview & Architecture

The training pipeline uses purely lexical and structural features extracted from URLs without any external HTTP requests (preventing SSRF and preserving privacy).

```text
Processed Dataset (url_dataset_clean.csv)
                │
                ▼
     Stratified Split (70/15/15)
     [Train: 2520 | Val: 540 | Test: 540]
                │
                ▼
     Feature Extraction (23 Features)
     via url_feature_extractor.py
                │
                ▼
     ColumnTransformer Preprocessing
     (StandardScaler on continuous, Passthrough on boolean)
                │
        ┌───────┴───────┐
        ▼               ▼
Logistic Regression   Random Forest
(Baseline 1)          (Baseline 2)
        │               │
        └───────┬───────┘
                ▼
     Evaluation on Validation & Test Sets
     (Accuracy, Precision, Recall, F1, ROC-AUC, FPR, FNR)
                │
                ▼
     Model Selection & Artifact Serialization
     (Saved as complete Pipeline into ml/models/url_model_v1.joblib)
```

---

## 2. Directory Structure

```text
ml/training/
├── config.py          # Centralized configuration (paths, hyperparameters, feature lists)
├── train.py           # Training execution script
└── README.md          # This documentation
```

---

## 3. Configuration & Hyperparameters

Configured in `ml/training/config.py`:

* **Random State**: `42` (ensures exact reproducibility across splits and estimators)
* **Dataset Splits**:
  * Training: 70% (2,520 samples)
  * Validation: 15% (540 samples)
  * Test: 15% (540 samples)
  * Stratification: Enabled on target label (`label = 0` benign, `label = 1` malicious)
* **Models Evaluated**:
  * **Logistic Regression**:
    * `C=1.0`, `max_iter=1000`, `class_weight='balanced'`, `random_state=42`
  * **Random Forest Classifier**:
    * `n_estimators=100`, `max_depth=15`, `min_samples_split=4`, `min_samples_leaf=2`, `class_weight='balanced'`, `random_state=42`, `n_jobs=-1`

---

## 4. How to Reproduce Training

Ensure the virtual environment is activated and dependencies from `ml/requirements.txt` are installed:

```bash
# Activate virtual environment (Windows PowerShell)
.\ml\.venv\Scripts\Activate.ps1

# Run the training script from the repository root
python ml/training/train.py
```

Or using module execution:

```bash
python -m ml.training.train
```

---

## 5. Artifacts Produced

Running the training pipeline generates:

1. **`ml/models/url_model_v1.joblib`**:
   The full serialized `sklearn.pipeline.Pipeline` containing both the fitted `ColumnTransformer` (scaler) and the trained classifier (`RandomForestClassifier`).
2. **`ml/models/url_model_v1_metadata.json`**:
   Metadata including model version, algorithm, training timestamp, sample counts, feature importances, and evaluated test metrics.
3. **`ml/evaluation/reports/model_comparison.json`**:
   Side-by-side comparison of Logistic Regression vs. Random Forest across all validation and test metrics.
