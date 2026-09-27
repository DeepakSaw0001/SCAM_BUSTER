# ScamBuster ML — Model Evaluation & Comparison (Phase 03)

This document details the evaluation methodology, performance metrics, confusion matrix analysis, and model selection rationale for ScamBuster's URL Machine Learning Classifier.

---

## 1. Evaluation Methodology

All models were evaluated on a strictly held-out test set of **540 URLs** (270 benign, 270 malicious) that were never seen during model fitting or hyperparameter validation.

To prevent data leakage:
* Exact URL duplicates and malformed records were removed prior to splitting.
* Train (70%), validation (15%), and test (15%) partitions were generated using stratified sampling (`random_state=42`).
* Feature transformations (`StandardScaler`) were fitted exclusively on the training set and applied uniformly to validation and test sets.

---

## 2. Model Comparison Report

The following metrics reflect **actual measured evaluation values** on the held-out test partition:

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC | False Positive Rate | False Negative Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Logistic Regression** (Baseline 1) | 0.9926 | 0.9963 | 0.9889 | 0.9926 | 0.9998 | 0.0037 (0.37%) | 0.0111 (1.11%) |
| **Random Forest Classifier** (Baseline 2) | **0.9963** | **1.0000** | **0.9926** | **0.9963** | **0.9999** | **0.0000 (0.00%)** | **0.0074 (0.74%)** |

---

## 3. Confusion Matrix Analysis (Selected Model: Random Forest)

On the test dataset of 540 URLs:

```text
                      PREDICTED BENIGN       PREDICTED MALICIOUS
ACTUAL BENIGN               270 (TN)                 0 (FP)
ACTUAL MALICIOUS              2 (FN)               268 (TP)
```

### Contextual Interpretation for ScamBuster

1. **True Negative (TN = 270)**:
   * Legitimate, standard URLs (e.g., standard domains, well-structured paths) correctly identified as safe.
   * Preserves normal user operations without friction.
2. **False Positive (FP = 0)**:
   * Legitimate URLs incorrectly flagged as phishing/malicious.
   * In a security scanning tool, high false positives erode user trust and cause alert fatigue. The Random Forest model achieved a **0.0% False Positive Rate** on the test set.
3. **False Negative (FN = 2)**:
   * Real phishing or malware URLs incorrectly classified as benign by the ML model.
   * This is the highest cybersecurity risk. The system mitigates this by using a **defense-in-depth architecture**: rule-based detection and heuristic indicators evaluate the URL concurrently with ML. If static rules trigger (e.g., credential keywords or numeric IP), the risk engine elevates the score even if ML false-negatives occur.
4. **True Positive (TP = 268)**:
   * Phishing and malicious URLs correctly flagged by structural and lexical patterns.
   * Achieved a **99.26% Recall** on hostile URLs.

---

## 4. Model Selection Rationale

The **Random Forest Classifier (`url_model_v1.joblib`)** was selected as the Phase 03 production baseline for the following concrete reasons:

1. **Superior Precision and Zero Test False Positives**:
   * Achieved 100% precision (0 false positives) compared to Logistic Regression's 1 false positive. For browser and end-user security tooling, avoiding false alarms on trusted sites is paramount.
2. **Higher Threat Recall (99.26% vs 98.89%)**:
   * Identified 268 of 270 malicious test URLs, missing only 2 stealthy patterns.
3. **Non-Linear Feature Interaction Modeling**:
   * URLs exhibit complex non-linear combinations (e.g., long paths with multiple dots and high digit ratios without HTTPS). Decision tree ensembles capture these joint interactions better than linear hyperplanes without manual interaction terms.
4. **Explainability via Feature Importance**:
   * Random Forest provides clear Gini-based feature importances, enabling ScamBuster's explainability layer to tell users *why* a URL was deemed risky (e.g., highlighting `path_length`, `path_depth`, `number_of_dots`, and `digit_ratio`).

---

## 5. Top Contributing Features

From empirical feature importance analysis:

1. `path_length` (22.8% importance): Phishing links frequently embed deep obfuscated paths and token strings.
2. `path_depth` (18.1% importance): Excessive slash nesting disguising legitimate-looking parent paths.
3. `number_of_dots` (14.2% importance): Subdomain stacking and faux file extensions (`.html.php`, `.co.secure`).
4. `url_length` (11.2% importance): Overall link bloat typical of credential harvesting campaigns.
5. `digit_ratio` (8.4% importance): High density of numbers used for randomized campaign IDs.
6. `number_of_digits` (6.9% importance): Raw count of digits across hostname and path.
7. `uses_https` (6.1% importance): Plaintext HTTP vs HTTPS distinction.
8. `hostname_length` (2.8% importance): Extended hostnames designed to emulate brand names.
