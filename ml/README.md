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

**Dataset:** Combined from public sources:
- Phishing URLs from OpenPhish community feed
- Legitimate URLs from the Tranco top-sites list
- Or a pre-built CSV dataset from public GitHub repositories

**Feature Engineering** (`features/url_features.py`): 17 structural features extracted from each URL:

| # | Feature | Description |
|---|---|---|
| 1 | `url_length` | Total character count |
| 2 | `hostname_length` | Length of the hostname |
| 3 | `path_length` | Length of the URL path |
| 4 | `num_dots` | Number of dots in the URL |
| 5 | `num_subdomains` | Number of subdomains |
| 6 | `num_digits` | Count of digit characters |
| 7 | `num_special_chars` | Count of special characters |
| 8 | `has_at_symbol` | Presence of `@` symbol |
| 9 | `has_ip_address` | Whether hostname is an IP address |
| 10 | `is_https` | Whether the scheme is HTTPS |
| 11 | `num_hyphens` | Count of hyphens |
| 12 | `num_query_params` | Number of query parameters |
| 13 | `path_depth` | Number of path segments |
| 14 | `has_double_slash_redirect` | `//` in path (redirect indicator) |
| 15 | `num_suspicious_keywords` | Count of phishing-related keywords |
| 16 | `digit_ratio` | Ratio of digits to total characters |
| 17 | `entropy` | Shannon entropy of the URL string |

**Why Random Forest?**
- Handles mixed feature types (counts, ratios, booleans) naturally
- Provides feature importance rankings
- Robust to outliers and doesn't require feature scaling
- Built-in ensemble reduces overfitting

**What is Shannon Entropy?**
A measure of randomness in the character distribution. Phishing URLs often use random-looking strings (e.g., `a8f2x9k.malicious-site.com`) which produce higher entropy than normal domain names.

---

## Evaluation Metrics

Both models are evaluated with:

- **Accuracy** — overall correct predictions / total predictions
- **Precision** — of all predicted positives, how many are actually positive
- **Recall** — of all actual positives, how many did we catch
- **F1 Score** — harmonic mean of precision and recall
- **Confusion Matrix** — full breakdown of true/false positives/negatives

Reports are saved as JSON in `evaluation/reports/`.

> **We do not manipulate metrics.** If a model performs poorly, we report the actual results and identify possible causes.

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
