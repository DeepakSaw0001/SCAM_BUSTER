# ScamBuster URL Dataset Documentation

## Overview
This directory stores datasets utilized for training and validating ScamBuster's supervised machine-learning URL classification models.

---

## 1. Raw Dataset: `raw/url_dataset.csv`

- **Dataset Name:** Phishing and Legitimate URL Curated Dataset
- **Sources:**
  - Malicious & Phishing URLs: Aggregated from PhishTank verified feeds, URLhaus (Abuse.ch), and open-source academic cybersecurity repositories.
  - Benign / Legitimate URLs: Sampled from top global domains (Tranco, Cisco Umbrella top 1M, university domains, and government portals).
- **Download / Collection Date:** 2026-09-25
- **License:** Open Academic / Research Use (Public Domain & ODC-By)
- **Format:** CSV (`url`, `label`)
- **Total Samples:** 3,600
- **Class Distribution:**
  - `label = 1` (Malicious / Phishing): 1,800 samples (50.0%)
  - `label = 0` (Benign / Legitimate): 1,800 samples (50.0%)
- **Missing Values:** 0
- **Duplicate URLs:** 0

### Label Definition
- `0`: **Benign** — Verified legitimate domain or web service with no known phishing or command-and-control behavior.
- `1`: **Malicious** — Confirmed phishing, credential harvesting portal, malware delivery host, or fake login landing page.

### Known Limitations
1. **Domain Age & Volatility:** Phishing infrastructure is ephemeral (often active for <48 hours). The dataset contains static lexical snapshots at collection time.
2. **Lexical Bias:** Some phishing campaigns employ look-alike characters (IDN homograph attacks) or compromised legitimate sub-pages that may exhibit fewer obvious lexical anomalies.
3. **No Active Network Signals:** The dataset does not capture dynamic DNS resolutions, HTTP response status codes, or SSL certificate transparency logs.

---

## 2. Processed Dataset: `processed/url_dataset_clean.csv`

The cleaned and normalized dataset produced by `ml/preprocessing/clean_url_dataset.py`:
- URLs normalized through `app.services.url_normalizer.normalize_url`.
- Stripped of illegal control characters and trailing whitespace.
- Verified binary label encoding (`0` or `1`).
- Deduplicated on canonical normalized URLs to prevent data leakage during train/val/test splits.
