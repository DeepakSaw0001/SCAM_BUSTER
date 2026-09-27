# ScamBuster — Machine Learning Subsystem

## Overview

ScamBuster uses **real machine-learning models** alongside its rule-based heuristic engines to detect suspicious messages and URLs. This `ml/` directory contains the complete ML pipeline: datasets, preprocessing, feature engineering, training, evaluation, inference, and a FastAPI service layer.

> **Important:** ML predictions are one signal among many. They do **not** constitute proof that a message or URL is malicious. The final risk assessment combines ML scores with the existing cybersecurity heuristic engines in a fusion layer.

---

## Why ML?

### Rule-based vs ML-based Detection

| Aspect | Rule-based (Heuristic) | Machine Learning |
|---|---|---|
| **How it works** | Hand-crafted patterns and keyword lists | Learns patterns from labelled data |
| **Strengths** | Transparent, no training needed, easy to audit | Generalises to unseen patterns, captures subtle signals |
| **Weaknesses** | Brittle, requires constant manual updates | Needs quality training data, less interpretable |
| **Best for** | Known, well-defined attack patterns | Catching novel/evolving threats |

ScamBuster uses **both** approaches. The heuristic engines catch known patterns reliably, while the ML models provide probabilistic scores for content that may not match any hand-crafted rule.

---

## Architecture

```
User Input
    ↓
Frontend (React)
    ↓
Node/Express API
    ↓
Python ML Service (FastAPI)   ← this subsystem
    ↓
Feature Extraction / Preprocessing
    ↓
Trained ML Model
    ↓
Prediction + Probability + Metadata
    ↓
(Future) Risk Fusion Engine
    ↓
MongoDB
```

---

## ML Pipelines

### Pipeline 1 — SMS/Message Spam Classification

**Goal:** Classify a text message as `ham` (legitimate) or `spam`.

**Dataset:** [UCI SMS Spam Collection](https://archive.ics.uci.edu/ml/datasets/sms+spam+collection)
- 5,574 SMS messages (4,827 ham, 747 spam)
- Publicly available, widely used in NLP research
- Labels: `ham` and `spam` (we preserve these labels rather than renaming to "scam")

**Pipeline:**
1. **Text Preprocessing** (`preprocessing/text_preprocessor.py`): lowercase, remove URLs/emails/phone numbers, strip punctuation, collapse whitespace
2. **TF-IDF Vectorisation** (`features/text_features.py`): unigram + bigram features, max 5000 terms, sublinear TF scaling
3. **Logistic Regression** classifier with balanced class weights
4. **Evaluation** on a stratified 80/20 train/test split

**Why Logistic Regression?**
- Strong baseline for text classification
- Produces well-calibrated probabilities
- Feature coefficients are directly interpretable (you can inspect which words drive the prediction)
- Fast to train and serve

**What is TF-IDF?**
Term Frequency–Inverse Document Frequency weights each word by how important it is to a specific document relative to the entire corpus. Common words like "the" get low weights; distinctive words like "winner" or "congratulations" get high weights. Using bigrams (pairs of adjacent words) captures phrases like "free prize" that single words would miss.

### Pipeline 2 — Phishing URL Classification

**Goal:** Classify a URL as `benign` or `malicious` (phishing).

### Pipeline 2 — URL Threat & Phishing Classification (Phase 03)

**Goal:** Classify an arbitrary URL as `benign` (0) or `malicious` (1) based purely on structural, lexical, and character-distribution patterns without dynamic network fetching (zero SSRF).

**Dataset:**
- Processed path: `ml/datasets/processed/url_dataset_clean.csv`
- Total samples: 3,600 verified balanced instances (1,800 Benign, 1,800 Malicious)
- Sources: PhishTank, URLhaus, Tranco / Cisco Umbrella top domains
- Cleaning: Deduplication, UTF-8 sanitization, protocol scheme validation, and missing label filtering

**Feature Engineering:**
Strictly unified 23 lexical/structural features extracted via `backend/app/services/url_feature_extractor.py` and documented in `ml/features/feature_definitions.md`:

| # | Feature | Type | Description |
|---|---|---|---|
| 1-5 | `url_length`, `hostname_length`, `path_length`, `query_length`, `fragment_length` | Continuous | Component length counts |
| 6-12 | `number_of_dots`, `number_of_hyphens`, `number_of_digits`, `number_of_special_characters`, `number_of_slashes`, `number_of_question_marks`, `number_of_equals` | Continuous | Punctuation, separator, and digit distributions |
| 13-15 | `subdomain_count`, `path_depth`, `query_parameter_count` | Continuous | URL structural complexity metrics |
| 16-18 | `has_ip_hostname`, `has_port`, `uses_https` | Boolean | Direct IP host, non-standard port, and TLS encryption status |
| 19-21 | `suspicious_keyword_count`, `has_at_symbol`, `has_double_slash_redirect` | Mixed | Credential keywords, authority spoofing, and path redirect sequences |
| 22-23 | `digit_ratio`, `entropy` | Float | Digit density and Shannon information entropy |

**Baseline Models Evaluated (Evaluated on Held-Out 540 Test URLs):**

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | FPR |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Logistic Regression** (Baseline 1) | 0.9926 | 0.9963 | 0.9889 | 0.9926 | 0.9998 | 0.37% |
| **Random Forest Classifier** (Selected Baseline 2) | **0.9963** | **1.0000** | **0.9926** | **0.9963** | **0.9999** | **0.00%** |

**Confusion Matrix (Random Forest on Test Set):**
- True Negatives (TN): 270
- False Positives (FP): 0 (0.0% False Positive Rate)
- False Negatives (FN): 2 (0.74% False Negative Rate)
- True Positives (TP): 268 (99.26% Recall)

**Artifacts & Versioning:**
- Artifact: `ml/models/url_model_v1.joblib` (Full pipeline with scaler + classifier)
- Metadata: `ml/models/url_model_v1_metadata.json`
- Model Version: `url-model-1.0`

---

## Training vs Inference

| Phase | What happens | When |
|---|---|---|
| **Training** | Load dataset → preprocess → extract features → fit model → evaluate → save artifacts | Once (or when retraining) |
| **Inference** | Load saved model → preprocess new input → extract features → predict | Every API request |

The trained model artifacts (`.joblib` files) are saved in `models/` and loaded once at service startup. This ensures predictions come from the actual trained model, not hardcoded values.

---

## Limitations

1. **Dataset scope:** The SMS Spam Collection contains ~5,500 messages from 2012. Modern scam messages may use different language patterns.
2. **Label mapping:** The text model predicts `ham`/`spam`, not `safe`/`scam`. Spam and scam are related but not identical concepts.
3. **URL features are structural:** The URL model only analyses the URL string itself — it does not fetch or analyse the page content.
4. **Class imbalance:** The SMS dataset is ~87% ham / 13% spam. We use `class_weight="balanced"` to compensate, but this is still a limitation.
5. **No real-time threat intelligence:** The models learn from historical data and cannot detect zero-day threats by themselves.
6. **Generalization:** Performance on the test set may not reflect real-world performance on different populations of messages/URLs.

---

## Directory Structure

```
ml/
├── api/                    # FastAPI inference service
│   ├── __init__.py
│   └── main.py
├── datasets/
│   ├── raw/                # Downloaded original datasets
│   └── processed/          # Cleaned, feature-engineered data
├── evaluation/
│   ├── __init__.py
│   ├── evaluate_text_model.py
│   ├── evaluate_url_model.py
│   └── reports/            # JSON evaluation reports
├── features/
│   ├── __init__.py
│   ├── text_features.py    # TF-IDF configuration
│   └── url_features.py     # URL feature extraction (17 features)
├── inference/
│   ├── __init__.py
│   ├── text_predictor.py   # predict_text() function
│   └── url_predictor.py    # predict_url() function
├── models/                 # Saved model artifacts (.joblib)
├── preprocessing/
│   ├── __init__.py
│   ├── text_preprocessor.py
│   └── url_preprocessor.py
├── training/
│   ├── __init__.py
│   ├── train_text_model.py
│   └── train_url_model.py
├── utils/
│   ├── __init__.py
│   └── model_utils.py
├── .gitignore
├── README.md
└── requirements.txt
```

---

## Quick Start

```bash
# 1. Create and activate virtual environment
cd ml/
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # Linux/Mac

# 2. Install dependencies
pip install -r requirements.txt

# 3. Train the text model (downloads UCI SMS Spam Collection)
python -m training.train_text_model

# 4. Train the URL model (downloads phishing URL data)
python -m training.train_url_model

# 5. (Optional) Re-evaluate models
python -m evaluation.evaluate_text_model
python -m evaluation.evaluate_url_model

# 6. Start the FastAPI service
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## API Endpoints

### `GET /health`
Returns service status and model availability.

### `POST /predict/text`
```json
{
    "text": "Congratulations! You've won a free iPhone. Click here to claim."
}
```
Response:
```json
{
    "prediction": "spam",
    "probability": 0.94,
    "spam_probability": 0.94,
    "model": "TF-IDF + Logistic Regression",
    "model_version": "1.0.0",
    "preprocessed_input": "congratulations youve won free iphone click here to claim"
}
```

### `POST /predict/url`
```json
{
    "url": "http://secure-login-verify.suspicious-site.com/account/update?id=12345"
}
```
Response:
```json
{
    "prediction": "malicious",
    "probability": 0.87,
    "malicious_probability": 0.87,
    "model": "URL Features + Random Forest",
    "model_version": "1.0.0",
    "features_used": 17,
    "extracted_features": { ... }
}
```

> **Note:** The example response values above are illustrative. Actual probabilities come from the trained model at inference time.

---

## Future Integration

The Node.js backend will communicate with this service via HTTP:

```
Node/Express  →  POST http://localhost:8000/predict/text  →  ML prediction
                                                           ↓
              ←  JSON response  ←  ←  ←  ←  ←  ←  ←  ←  ←
```

The ML prediction will be combined with the heuristic engine scores in a **Risk Fusion Engine** to produce a final risk assessment. This integration is planned for the next development step.
