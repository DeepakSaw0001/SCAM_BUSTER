# ScamBuster ML — SMS Spam Collection Dataset Documentation

## 1. Dataset Overview

* **Dataset Name:** SMS Spam Collection v.1
* **Primary Source:** UCI Machine Learning Repository / Almeida & Gómez Hidalgo
* **Source URL:** [https://archive.ics.uci.edu/ml/datasets/sms+spam+collection](https://archive.ics.uci.edu/ml/datasets/sms+spam+collection)
* **Licence:** Creative Commons Attribution 4.0 International (CC BY 4.0) / Public domain for academic and security research.
* **Acquisition Date:** Verified and structured for Phase 04 reproducible ML pipeline.
* **Format:** Tab-separated text (`label\tmessage`).

---

## 2. Compilation Sources

The dataset synthesizes real-world mobile messages collected from verified research sources:
1. **Grumbletext UK:** 425 manually verified SMS spam/phishing submissions reported by mobile users.
2. **Caroline Tag's PhD Thesis:** 450 verified legitimate personal SMS messages.
3. **NUS SMS Corpus (National University of Singapore):** 3,375 legitimate SMS messages contributed by student volunteers.
4. **SMS Spam Corpus v.0.1 Big (Gómez Hidalgo):** 1,002 legitimate messages and 322 spam messages.

---

## 3. Measured Dataset Statistics

### Raw Dataset (`ml/datasets/raw/SMSSpamCollection`)
* **Total Records:** 5,572
* **Missing Values:** 0
* **Class Distribution (Raw):**
  * `ham` (legitimate): 4,825 (86.60%)
  * `spam` (fraud / unwanted): 747 (13.40%)
* **Duplicate Messages:** 403 records
* **Messages Containing URLs:** 108 records (95% in spam class)
* **Average Message Length:** 80.49 characters

### Clean & Deduplicated Dataset (`ml/datasets/processed/sms_spam_clean.csv`)
* **Total Unique Records:** 5,169
* **Class Distribution (Clean):**
  * `ham`: 4,516 (87.37%)
  * `spam`: 653 (12.63%)
* **Conflicting Labels:** 0 (no messages share ambiguous ham/spam annotations)

---

## 4. Label Mapping

The dataset provides raw binary string labels mapped explicitly into ScamBuster's unified threat schema:

| Raw Dataset Label | ScamBuster Encoded Label | Classification Meaning | Interpretation in ScamBuster |
|---|:---:|---|---|
| `ham` | `0` | Legitimate / Normal Communication | Benign personal or transactional message |
| `spam` | `1` | Scam / Smishing / Fraudulent | Social engineering, lottery lure, credential theft |

> **Academic Rigor Note:** The dataset's original label is "spam". While many messages in this class represent aggressive advance-fee fraud, banking smishing, and fake lottery rewards, we maintain a clear distinction: ML classification is a probabilistic statistical signal that must be combined with deterministic cybersecurity heuristics in the ScamBuster Unified Risk Engine.

---

## 5. Known Limitations

1. **Geographic & Linguistic Bias:** The corpus consists predominantly of English-language SMS messages from the UK and Singapore. It may underrepresent non-English lures or regional SMS phishing dialects.
2. **Temporal Drift:** SMS scams have evolved since the dataset's compilation, increasingly incorporating zero-font unicode tricks, regional banking OTP templates, and modern URL shorteners.
3. **Class Imbalance:** Only 12.63% of clean messages are spam. Models must employ `class_weight='balanced'` and stratified splitting to prevent majority-class bias.
