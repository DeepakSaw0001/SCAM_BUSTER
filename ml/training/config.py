"""
ScamBuster ML — URL Classifier Training Configuration
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ML_DIR = REPO_ROOT / "ml"

# Dataset paths
RAW_DATASET_PATH = ML_DIR / "datasets" / "raw" / "url_dataset.csv"
CLEAN_DATASET_PATH = ML_DIR / "datasets" / "processed" / "url_dataset_clean.csv"

# Output artifacts
MODELS_DIR = ML_DIR / "models"
MODEL_ARTIFACT_PATH = MODELS_DIR / "url_model_v1.joblib"
METADATA_PATH = MODELS_DIR / "url_model_v1_metadata.json"

# Evaluation reports
REPORTS_DIR = ML_DIR / "evaluation" / "reports"
COMPARISON_REPORT_PATH = REPORTS_DIR / "model_comparison.json"

# Reproducibility & Data Splits
RANDOM_STATE = 42
TEST_SIZE = 0.15
VAL_SIZE = 0.15

# Continuous / Numerical Features (Scaled via StandardScaler)
NUMERICAL_FEATURES = [
    "url_length",
    "hostname_length",
    "path_length",
    "query_length",
    "fragment_length",
    "number_of_dots",
    "number_of_hyphens",
    "number_of_digits",
    "number_of_special_characters",
    "number_of_slashes",
    "number_of_question_marks",
    "number_of_equals",
    "subdomain_count",
    "path_depth",
    "query_parameter_count",
    "suspicious_keyword_count",
    "digit_ratio",
    "entropy",
]

# Binary / Boolean Features (Pass-through)
BOOLEAN_FEATURES = [
    "has_ip_hostname",
    "has_port",
    "uses_https",
    "has_at_symbol",
    "has_double_slash_redirect",
]

# Model Hyperparameters
LOGISTIC_REGRESSION_PARAMS = {
    "C": 1.0,
    "max_iter": 1000,
    "class_weight": "balanced",
    "random_state": RANDOM_STATE,
}

RANDOM_FOREST_PARAMS = {
    "n_estimators": 100,
    "max_depth": 15,
    "min_samples_split": 4,
    "min_samples_leaf": 2,
    "class_weight": "balanced",
    "random_state": RANDOM_STATE,
    "n_jobs": -1,
}
