# ScamBuster Phase 04 — SMS & Text Message Scam Detection

## Executive Overview

Phase 04 introduces ScamBuster's second primary detection modality: **SMS and Text Message Scam Detection**.
The modality couples deterministic cybersecurity heuristics with an empirical classical NLP machine learning model (TF-IDF + Calibrated LinearSVC) and static embedded URL analysis to detect smishing, credential harvesting, urgency extortion, and lottery lures without sending outbound network requests or storing sensitive raw SMS text.

---

## 1. Dataset Documentation

* **Dataset Name:** SMS Spam Collection v.1
* **Source:** UCI Machine Learning Repository / Almeida & Gómez Hidalgo ([https://archive.ics.uci.edu/ml/datasets/sms+spam+collection](https://archive.ics.uci.edu/ml/datasets/sms+spam+collection))
* **License:** Creative Commons Attribution 4.0 International (CC BY 4.0)
* **Compilation Sources:**
  1. Grumbletext UK (425 verified mobile spam submissions)
  2. Caroline Tag's PhD Thesis (450 verified legitimate personal SMS)
  3. NUS SMS Corpus (3,375 legitimate mobile SMS from Singapore)
  4. Gómez Hidalgo SMS Spam Corpus (1,002 legitimate, 322 spam)

### Measured Dataset Statistics

| Metric | Raw Dataset | Clean & Deduplicated Dataset |
|---|---|---|
| **Total Messages** | 5,572 | 5,167 |
| **Ham (Legitimate)** | 4,825 (86.60%) | 4,516 (87.40%) |
| **Spam (Fraud / Unwanted)** | 747 (13.40%) | 651 (12.60%) |
| **Duplicate Messages** | 403 removed | 0 duplicates |
| **Missing Values** | 0 | 0 |
| **Average Character Length** | 80.49 chars | 79.92 chars |

### Label Mapping

| Raw Dataset Annotation | ScamBuster Binary Label | Risk Engine Semantics |
|---|:---:|---|
| `ham` | `0` | Legitimate / Benign Baseline |
| `spam` | `1` | Scam / Smishing / Fraudulent |

---

## 2. Text Preprocessing Pipeline

Implemented in [`backend/app/services/message_preprocessor.py`](file:///d:/vibe_coding/SCAM_BUSTER/backend/app/services/message_preprocessor.py):

1. **Unicode NFKC Normalization:** Neutralizes full-width characters, homoglyphs, and zero-width spaces.
2. **Whitespace Normalization:** Collapses irregular and excessive spacing.
3. **Safe Entity Extraction:**
   * Embedded URLs via regex (captured for static lexical inspection, never fetched)
   * Phone numbers (validated for 7–15 digits)
   * Email addresses
4. **Token Normalization for NLP:**
   * Lowercasing
   * Removal of URLs, emails, and phone numbers to prevent trivial memorization
   * Punctuation stripping
   * Clean token stream generation for TF-IDF vectorization

> **Stylistic Preservation:** The original raw message is preserved separately during processing to extract stylistic metrics (e.g. uppercase ratio, exclamation counts) that serve as heuristic signals.

---

## 3. Feature Engineering

Implemented in [`backend/app/services/message_feature_extractor.py`](file:///d:/vibe_coding/SCAM_BUSTER/backend/app/services/message_feature_extractor.py):

### Statistical Features (10)
* `message_length`: Total raw character count
* `word_count`: Whitespace-delimited word tokens
* `character_count`: Non-whitespace character count
* `sentence_count`: Delimited by sentence-ending punctuation (`.`, `!`, `?`)
* `average_word_length`: Mean length per word
* `uppercase_ratio`: Proportion of letters that are capitalized
* `digit_ratio`: Proportion of digits relative to length
* `special_character_ratio`: Proportion of non-alphanumeric symbols
* `exclamation_count`: Frequency of exclamation marks (`!`)
* `question_mark_count`: Frequency of question marks (`?`)

### Structural Features (6)
* `url_count`, `phone_number_count`, `email_count`
* `has_url`, `has_phone_number`, `has_email`

### Semantic Keyword Dictionaries (7)
* `urgency_terms_count`: Psychological coercion (`urgent`, `immediately`, `within 24 hours`, `expires`, etc.)
* `credential_terms_count`: Security token harvesting (`otp`, `password`, `pin`, `passcode`, `verify account`, etc.)
* `financial_terms_count`: Payment lure terms (`bank`, `wire`, `refund`, `overdue`, `transfer`, `crypto`, etc.)
* `threat_terms_count`: Intimidation language (`suspended`, `locked`, `warrant`, `legal action`, `arrest`, etc.)
* `reward_terms_count`: Advance-fee prize lures (`winner`, `lottery`, `jackpot`, `claim prize`, `voucher`, etc.)
* `authority_terms_count`: Brand and institutional impersonation (`irs`, `usps`, `chase`, `wells fargo`, `paypal`, etc.)
* `call_to_action_count`: Action triggers (`click`, `visit`, `reply`, `call`, `download`, `confirm`, etc.)

---

## 4. NLP Model Architecture & TF-IDF Configuration

* **Representation:** `TfidfVectorizer`
* **N-Gram Range:** `(1, 2)` (captures both unigrams like `"verify"` and bigrams like `"verify account"`, `"act immediately"`)
* **Sublinear TF:** `True` (applies logarithmic sublinear term frequency scaling: `1 + log(tf)`)
* **Min DF:** `2` (removes unique singleton noise)
* **Max DF:** `0.95` (removes corpus-wide stopword noise)
* **Max Features:** `5,000` features

---

## 5. Model Evaluation & Comparison

Trained with a **reproducible stratified split** (`random_state=42`):
* **Train Set:** 3,616 samples (70%)
* **Validation Set:** 775 samples (15%)
* **Held-Out Test Set:** 776 samples (15%)

### Measured Evaluation Metrics (Held-Out Test Set)

| Model Pipeline | Accuracy | Precision | Recall | F1-Score | ROC-AUC | False Positive Rate | False Negative Rate |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **TF-IDF + Logistic Regression** | 97.42% | 89.80% | **89.80%** | 89.80% | 0.9799 | 1.47% (10 / 678) | 10.20% (10 / 98) |
| **TF-IDF + Calibrated LinearSVC** | **98.20%** | **97.73%** | 87.76% | **92.47%** | **0.9846** | **0.29% (2 / 678)** | 12.24% (12 / 98) |

### Confusion Matrix on Held-Out Test Set (Calibrated LinearSVC)

```text
                     Actual Legitimate (Ham)    Actual Scam (Spam)
Predicted Benign:            676 (TN)                   12 (FN)
Predicted Scam:                2 (FP)                   86 (TP)
```

---

## 6. Model Selection Rationale

**Calibrated LinearSVC** was selected as ScamBuster's production classifier artifact (`message_model_v1.joblib`):
1. **Low False Positive Rate (0.29%):** Out of 678 legitimate test messages, only 2 were flagged as false positives. In anti-scam security tooling, excessive false alarms destroy user trust.
2. **Superior F1-Score (92.47% vs. 89.80%):** Higher overall balance of precision and recall.
3. **Calibrated Probabilities:** Using 3-fold cross-validation calibration allows the Linear Support Vector Classifier to output mathematically grounded probabilistic confidence scores that feed directly into ScamBuster's Unified Risk Engine.
4. **Lightweight & Fast:** Under 350 KB serialized artifact size and sub-millisecond inference time.

---

## 7. Unified Risk Engine Integration

The message scanner integrates with ScamBuster's Unified Risk Engine:

```text
                 SMS Input
                     │
         ┌───────────┴───────────┐
         ▼                       ▼
  Message Rules (0-100)    Message ML (0-100)
         │                       │
         └───────────┬───────────┘
                     │
                     ▼
          Embedded URL Static Scanner
          (Lexical Only — Zero SSRF)
                     │
                     ▼
            Unified Risk Scorer
            • Composite Score (0-100)
            • Calibrated Risk Level
            • Agreement Confidence
            • Explainability Reasons
```

### Defense-in-Depth Guardrails:
* **Critical Rule Guardrail:** An explicit credential or OTP harvesting request sets a composite score floor of ≥ 75.
* **Strong ML Signal Guardrail:** High ML predicted probability (≥ 85%) with any heuristic indicator elevates score to ≥ 70.
* **Malicious Embedded Link Guardrail:** If an embedded link triggers critical URL phishing heuristics (e.g. numeric IP host, credential path), the link threat score elevates the overall message risk.
* **Clean Baseline Guardrail:** Messages with zero rules, low ML (≤ 10%), and clean links are capped at ≤ 5.
* **UNKNOWN Condition:** Extremely short or ambiguous inputs (fewer than 5 characters or zero tokens) return `risk_level="unknown"` with 0.0 confidence.

---

## 8. Privacy & Security Protections

1. **Zero Outbound Requests:** URLs extracted from SMS messages are inspected purely through lexical and static path analysis. The backend never fetches, crawls, or resolves external domains (zero SSRF).
2. **Data Minimization:** Raw message contents, OTPs, personal names, account numbers, and phone numbers are never stored in the database.
3. **Log Sanitization:** Application logs record only operational metadata (`scan_id`, `char_count`, `word_count`, `risk_level`, `composite_score`), never the text content.
4. **Untrusted Input Sanitation:** Message text is treated strictly as data; prompt injection attempts or executable code embedded within text are handled purely as static strings.

---

## 9. Reproducibility

To re-run data cleaning, stratified splitting, model training, evaluation, and artifact packaging from scratch:

```bash
python ml/training/train_message_model.py
```

Outputs:
* `ml/datasets/processed/sms_spam_clean.csv`
* `ml/models/message_model_v1.joblib`
* `ml/models/message_model_v1_metadata.json`
* `ml/evaluation/reports/message_model_comparison.json`
* Automatically synchronized to `backend/app/ml/models/` for immediate production inference.
