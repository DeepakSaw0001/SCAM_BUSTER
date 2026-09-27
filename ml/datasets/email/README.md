# ScamBuster ML — Email Spam & Phishing Dataset Documentation

## 1. Dataset Overview

* **Dataset Name:** Apache SpamAssassin Public Corpus (20021010 Easy Ham & 20021010 Spam)
* **Primary Source:** Apache Software Foundation / SpamAssassin Project
* **Source URL:** [https://spamassassin.apache.org/old/publiccorpus/](https://spamassassin.apache.org/old/publiccorpus/)
* **License:** Apache License 2.0 / Public Academic and Security Research
* **Acquisition Date:** 2026-09-25 (Automated extraction and MIME parsing pipeline)
* **Raw Files:**
  * `ml/datasets/raw/20021010_spam.tar.bz2` (1,192,582 bytes)
  * `ml/datasets/raw/20021010_easy_ham.tar.bz2` (1,677,144 bytes)
* **Processed Target:** `ml/datasets/processed/email_corpus_clean.csv`

---

## 2. Compilation & Architecture

The corpus contains authentic, full RFC-822 formatted email messages collected from real mailboxes and spam traps:
1. **Easy Ham:** Real-world legitimate personal, mailing list, and business correspondence with complete mail headers (`Received`, `From`, `To`, `Date`, `Subject`, `Message-ID`, etc.).
2. **Spam / Phishing:** Verified unsolicited commercial email, financial advance-fee fraud, banking credential lures, and urgent scam campaigns.

---

## 3. Measured Dataset Statistics

### Raw Parsed Records
* **Total Parsed:** 2,001
* **Raw Ham (0):** 1,500 (74.96%)
* **Raw Spam/Phishing (1):** 501 (25.04%)

### Deduplicated & Cleaned Dataset (`email_corpus_clean.csv`)
* **Total Unique Records:** 1,926
* **Clean Ham (0):** 1,455 (75.55%)
* **Clean Spam/Phishing (1):** 471 (24.45%)
* **Deduplication Strategy:** Exact duplicate body removal, subject hash indexing, and elimination of uninformative text snippets (< 10 characters).
* **Missing Values:** 0

---

## 4. Label Mapping

| Raw Dataset Source | ScamBuster Numeric Label | Classification Meaning | ScamBuster Interpretation |
|---|:---:|---|---|
| `easy_ham` | `0` | Legitimate / Clean | Normal human correspondence, legitimate notifications |
| `spam` | `1` | Spam / Phishing / Fraud | Fraudulent solicitation, credential theft, financial lure |

---

## 5. Leakage Prevention Strategy

1. **Exact-Duplicate Removal:** Removed identical campaign bodies before dataset splitting to ensure no test sample appears identically in training.
2. **Stratified Splitting:** 80% Train, 20% Held-Out Test, maintaining exact class distribution across folds.
3. **Pipeline Encapsulation:** Vectorizers and transformers are fit strictly on training splits and only applied to test splits.

---

## 6. Known Limitations

1. **Temporal Horizon:** The core SpamAssassin public corpus dates from historical spam collections; modern adversarial techniques (such as QR codes / quishing or novel zero-day brands) are augmented via ScamBuster's dynamic heuristic rules and URL scanner fusion.
2. **Language Distribution:** Primarily English-language correspondence.
3. **Header Authenticity:** In training data, mail server authentication headers (e.g., modern DKIM and DMARC verification tags) reflect older mail server configurations; ScamBuster's dedicated header rule engine handles modern SPF/DKIM/DMARC headers deterministically during live inference.
