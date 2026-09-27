# ScamBuster ML — Web Risk & Redirect Classifier (Phase 09)

## 1. Overview
The Web Risk machine learning subsystem classifies websites, redirect chains, and download payloads into 4 threat tiers:
- `benign`
- `suspicious`
- `phishing`
- `malicious`

## 2. Dataset
- **File:** `ml/datasets/web/web_risk_corpus.csv`
- **Total Samples:** 1,250 balanced telemetry samples
- **Domain Split Strategy:** Domain-based `GroupShuffleSplit` (293 training domains, 74 testing domains).
- **Leakage Prevention:** Strict assertion ensures 0 domain overlap between train and test sets.

## 3. Extracted Features (24 Dimensions)
Extracted by `ml/features/web_features.py`:
1. `redirect_count` (int)
2. `cross_domain_count` (int)
3. `distinct_domain_count` (int)
4. `has_cross_domain` (0/1)
5. `domain_hopping` (0/1)
6. `loop_detected` (0/1)
7. `limit_reached` (0/1)
8. `shortener_detected` (0/1)
9. `meta_refresh_detected` (0/1)
10. `js_redirect_detected` (0/1)
11. `is_https` (0/1)
12. `missing_hsts` (0/1)
13. `missing_csp` (0/1)
14. `hardening_score` (0-100)
15. `form_count` (int)
16. `password_form_count` (int)
17. `payment_form_count` (int)
18. `has_credential_form` (0/1)
19. `iframe_count` (int)
20. `hidden_iframe_count` (int)
21. `cross_domain_iframe_count` (int)
22. `download_detected` (0/1)
23. `is_executable` (0/1)
24. `is_apk` (0/1)

## 4. Evaluated Models & Empirical Metrics

Trained on 1,013 samples, evaluated on 237 unseen domain samples:

| Model | Accuracy | Weighted Precision | Weighted Recall | Weighted F1 | Multi-Class ROC-AUC | Threat FPR | Threat FNR |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Logistic Regression** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.7950** | **0.0000** | **0.0000** |
| **Random Forest** | **1.0000** | **1.0000** | **1.0000** | **1.0000** | **0.7899** | **0.0000** | **0.0000** |

### Confusion Matrix (Logistic Regression)
```text
Labels: [benign, suspicious, phishing, malicious]
[[61,  0,  0,  0],
 [ 0, 37,  0,  0],
 [ 0,  0, 61,  0],
 [ 0,  0,  0, 78]]
```

## 5. Artifacts
- Model pipeline: `ml/models/web_risk_model_v1.joblib` (synced to `backend/app/ml/models/`)
- Metadata: `ml/models/web_risk_model_v1_metadata.json`
