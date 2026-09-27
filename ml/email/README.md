# ScamBuster — Email Phishing & Scam Detection (Phase 05)

## 1. Overview & Objectives

Phase 05 establishes ScamBuster's third core threat detection modality: **Email Scam and Phishing Detection**. The system analyzes raw RFC-822 MIME emails, `.eml` file exports, or structured JSON payloads using a defense-in-depth pipeline combining:
1. **RFC-822 / MIME Parsing & Preprocessing**: Safe extraction of headers, bodies, authentication results, and attachment metadata.
2. **Deterministic Cybersecurity Heuristics**: From/Reply-To divergence, reported SPF/DKIM/DMARC authentication failures, deceptive visual hyperlinks (anchor mismatches), dangerous attachment formats, and embedded credential capture forms.
3. **Statistical NLP Classification**: TF-IDF (unigrams + bigrams) + Calibrated Linear Support Vector Classifier (LinearSVC), trained on the benchmark Apache SpamAssassin email corpus.
4. **Static Embedded URL Intelligence**: Seamless static analysis of extracted links using ScamBuster's Phase 03 URL security engine (zero outbound requests, SSRF immune).
5. **Unified Risk Engine**: Modality-independent multi-signal fusion, producing calibrated risk scores (0–100), risk tiers, threat categories, and explainable reasons.

---

## 2. Dataset Documentation

* **Dataset Name:** Apache SpamAssassin Public Corpus (20021010 Easy Ham & 20021010 Spam)
* **Primary Source:** Apache Software Foundation / SpamAssassin Project
* **Source URL:** [https://spamassassin.apache.org/old/publiccorpus/](https://spamassassin.apache.org/old/publiccorpus/)
* **License:** Apache License 2.0 / Public Research and Cybersecurity Use
* **Acquisition Date:** 2026-09-25 (Automated extraction & MIME decoding pipeline)
* **Raw Files:**
  * `ml/datasets/raw/20021010_spam.tar.bz2` (1.19 MB)
  * `ml/datasets/raw/20021010_easy_ham.tar.bz2` (1.68 MB)
* **Processed Dataset:** `ml/datasets/processed/email_corpus_clean.csv`
* **Sample Count (Unique, Deduplicated):** 1,926 records
  * **Ham (Class 0):** 1,455 (75.55%)
  * **Spam / Phishing (Class 1):** 471 (24.45%)
* **Leakage Prevention Strategy:**
  * Exact body and subject duplicate removal prior to splitting.
  * Stratified 70% Train (1,348) / 15% Validation (289) / 15% Held-Out Test (289) split.
  * Vectorizers and feature transformers are fit strictly on the training partition.

---

## 3. Email Processing & Security Principles

```text
Email (Raw text / .eml)
  │
  ├───────────────────────────────────┐
  │                                   │
  ▼                                   ▼
RFC-822 MIME Headers             HTML & Body Extraction
  │                                   │
  ├─ From & Reply-To Domains          ├─ Safe Tag Stripping (Zero JS Execution)
  ├─ SPF / DKIM / DMARC Results       ├─ Visual Anchor vs. Destination Check
  ├─ Received Chain (Hop Count)       └─ Attachment Metadata (Extension, Size)
  │                                   │
  ▼                                   ▼
Email Rule Detector              Statistical NLP Classifier
  │                              (TF-IDF + Calibrated LinearSVC)
  └─────────────────┬─────────────────┘
                    │
                    ▼
          URL Extraction Engine
                    │
                    ▼
          Static URL Analyzer
          (Phase 03 Pipeline Reuse)
                    │
                    ▼
          Unified Risk Engine
                    │
          ┌─────────┴─────────┐
          ▼                   ▼
     Risk Score          Explainability
      (0-100)           (Indicators & Why Flagged)
```

### Security & Privacy Guarantees
1. **Zero External Network Lookups:** No DNS queries, no SMTP handshakes, and no remote asset/tracking image fetching. Prevents SSRF vulnerabilities completely.
2. **Untrusted Headers Principle:** `From` headers are treated as claims, not cryptographic proof. Authentication results (SPF/DKIM/DMARC) are analyzed as reported evidence.
3. **Safe HTML Handling:** HTML is parsed statically for link/form structures; scripts and iframes are stripped without execution.
4. **No Attachment Detonation:** Attachments are evaluated strictly via metadata (filename, extension, MIME type, double-extension signatures). Executable code is never executed.
5. **Privacy Preservation:** Raw email bodies, full recipient directories, and credentials are never written to application logs. The logged `target` descriptor is sanitized.

---

## 4. Feature Extraction & Heuristic Rules

### Structured Feature Categories
* **Text Metrics:** `subject_length`, `body_length`, `word_count`, `line_count`, `uppercase_ratio`, `digit_ratio`, `special_char_ratio`.
* **Keyword Detectors:** `urgency_keyword_count`, `credential_keyword_count`, `financial_keyword_count`.
* **Hyperlink Indicators:** `url_count`, `unique_domain_count`, `anchor_mismatch_count`, `html_form_count`, `html_hidden_element_count`.
* **Sender & Infrastructure:** `sender_replyto_mismatch`, `received_hops_count`, `auth_failure_detected`.
* **Attachment Signatures:** `attachment_count`, `suspicious_attachment_count`, `double_extension_count`.

### Deterministic Heuristic Rules
| Rule ID | Rule Name | Severity | Score Weight | Description |
|---|---|:---:|:---:|---|
| `RULE_EMAIL_ANCHOR_MISMATCH` | Deceptive Hyperlink | CRITICAL | 40 | Displayed text advertises trusted brand/domain, but href destination redirects to an external host |
| `RULE_EMAIL_DOUBLE_EXTENSION_ATTACHMENT` | Double-Extension Signature | CRITICAL | 40 | Attachment utilizes double extension (e.g., `.pdf.exe`) to masquerade executable binaries |
| `RULE_EMAIL_SENDER_REPLYTO_MISMATCH` | Address Spoofing Indicator | HIGH | 30 | `From` domain diverges from `Reply-To` domain to divert replies |
| `RULE_EMAIL_AUTH_FAILURE` | Mail Authentication Failure | HIGH | 35 | Headers explicitly record SPF, DKIM, or DMARC `fail`/`softfail` |
| `RULE_EMAIL_SUSPICIOUS_ATTACHMENT` | High-Risk Attachment Format | HIGH | 35 | Attachment matches executable or script formats (`.exe`, `.scr`, `.bat`, `.vbs`, etc.) |
| `RULE_EMAIL_CREDENTIAL_SOLICITATION` | Credential Solicitation | HIGH | 25 | Solicits login credentials, passwords, or account verification |
| `RULE_EMAIL_HTML_FORM` | Embedded Interactive HTML Form | HIGH | 25 | Body contains embedded `<form>` elements designed for in-client credential capture |
| `RULE_EMAIL_URGENCY_THREAT` | Urgency & Coercion | MEDIUM | 20 | High-pressure urgency or punitive account suspension threats |
| `RULE_EMAIL_FINANCIAL_LURE` | Advance-Fee Financial Lure | MEDIUM | 20 | Unsolicited wire transfer, lottery prize, or inheritance promise |

---

## 5. Machine Learning Models & Evaluation

Two classical NLP baseline pipelines were trained and evaluated on the 70/15/15 stratified partition:
* **Model 1:** TF-IDF (8,000 features, unigrams + bigrams, english stopwords) + Logistic Regression (`C=2.0`, `solver="liblinear"`)
* **Model 2:** TF-IDF (8,000 features, unigrams + bigrams, english stopwords) + Calibrated LinearSVC (`C=1.0`, 3-fold sigmoid calibration)

### Empirical Evaluation on Held-Out Test Set (289 samples)

| Metric | Logistic Regression | Calibrated LinearSVC (Selected) |
|---|:---:|:---:|
| **Accuracy** | 98.62% | **100.00%** |
| **Precision** | 100.00% | **100.00%** |
| **Recall** | 94.37% | **100.00%** |
| **F1 Score** | 0.9710 | **1.0000** |
| **ROC-AUC** | 1.0000 | **1.0000** |
| **False Positive Rate (FPR)** | 0.00% | **0.00%** |
| **False Negative Rate (FNR)** | 5.63% | **0.00%** |
| **Confusion Matrix (TN / FP / FN / TP)** | 218 / 0 / 4 / 67 | **218 / 0 / 0 / 71** |

### Selected Production Artifacts
* **Model Pipeline:** `ml/models/email_model_v1.joblib` (synchronized with `backend/app/ml/models/email_model_v1.joblib`)
* **Metadata:** `ml/models/email_model_v1_metadata.json`
* **Comparison Report:** `ml/evaluation/reports/email_model_comparison.json`

---

## 6. API Endpoints

### 1. `POST /api/v1/scan/email`
Accepts JSON with raw email text or structured fields:
```json
{
  "raw_email": "From: Security <security@chase.com>\nReply-To: phish@evil.xyz\nSubject: Urgent: Verify Account\n\nPlease login at http://phish.xyz/login"
}
```
Or structured fields:
```json
{
  "sender": "Chase Bank <fraud@service-update.xyz>",
  "subject": "Action Required: Account Restricted",
  "body": "Please confirm your password immediately.",
  "reply_to": "divert@phishing-target.net",
  "attachments": ["Invoice_3892.pdf.exe"]
}
```

### 2. `POST /api/v1/scan/email/upload`
Accepts `multipart/form-data` with an `.eml` file (max 5MB). Parses RFC-822 bytes directly without writing untrusted executable binaries to disk.

---

## 7. Limitations & Future Roadmap

1. **Passive Header Ingestion:** SPF, DKIM, and DMARC are analyzed as reported by receiving MTAs in the provided headers. Active DNS/cryptographic validation requires live resolver access (Phase 06+ isolated network subsystem).
2. **Attachment Payloads:** Only metadata is inspected statically in this phase. Deep binary dynamic detonation belongs to isolated sandbox microservices.
