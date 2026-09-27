# ScamBuster ML — Phone Number Scam Detection (Phase 06)

## 1. Overview & Architecture

ScamBuster Phase 06 introduces telephone scam and robocall intelligence. The architecture incorporates:
* International telephone normalization using `libphonenumber` (`python-phonenumbers`).
* Privacy-preserving processing: zero raw phone numbers in logs or unkeyed storage; keyed HMAC-SHA256 representation for internal caching and lookup; masked representation (`+91 ******3210`) for presentation.
* Static telephony features (validity, length, numbering plans, number types).
* Digit pattern analysis (Shannon entropy, sequential ascending/descending digit runs, digit repetition).
* Classical tabular machine learning classifier (Random Forest vs Logistic Regression).
* Modular threat intelligence provider abstraction with TTL caching and in-flight deduplication.
* Unified Risk Engine integration with transparent uncertainty ("Not Reported != Safe").

---

## 2. Dataset Information

* **Corpus Name**: ScamBuster Phone Scam & Telephony Reputation Corpus (v1.0)
* **Dataset Location**: `ml/datasets/processed/phone_corpus_clean.csv`
* **Primary Sources**:
  * US Federal Trade Commission (FTC) Do Not Call (DNC) Reported Robocalls & Telemarketing Complaints (Open Government Data).
  * Federal Communications Commission (FCC) Consumer Complaints robocall registries.
  * ITU-T standard telecom allocation prefix tables and verified institutional helplines (e.g., public bank toll-free numbers, emergency services).
* **Sample Count**: 4,130 unique records after strict deduplication:
  * Legitimate / Verified Directory Numbers (`0`): 2,326
  * Reported Scam / Robocall / Wangiri Numbers (`1`): 1,804
* **Leakage Prevention**: Numbers were normalized to canonical E.164 and deduplicated *before* performing an 80/20 stratified train/test split. No telephone number appears in both train and test partitions.

---

## 3. Label Mapping

* `0` (`LEGITIMATE`): Numbers conforming to legitimate institutional directories, official utility helplines, or valid standard ITU-T subscriber ranges.
* `1` (`REPORTED_SCAM`): Numbers with consumer fraud complaint records, unallocated spoofed exchanges, or known Wangiri high-tariff callback prefixes.
* `UNKNOWN`: Evaluated dynamically at inference time when evidence is insufficient.

---

## 4. Feature Engineering

18 static structural and mathematical pattern features (`PHONE_FEATURE_NAMES`):
1. `country_code`: Calling code (e.g., 91, 1, 44).
2. `number_length`: Total E.164 digit count.
3. `national_number_length`: Subscriber national digit length.
4. `is_valid_number`: Boolean indicator (1/0) from libphonenumber.
5. `is_possible_number`: Structural length validity (1/0).
6. `is_mobile`: Mobile / cellular line type (1/0).
7. `is_fixed_line`: Landline type (1/0).
8. `is_voip`: Virtual / VoIP telephony (1/0).
9. `is_premium_rate`: Premium-rate tariff prefix (1/0).
10. `is_toll_free`: Toll-free helpline prefix (1/0).
11. `digit_entropy`: Shannon entropy $H(X) = -\sum p_i \log_2(p_i)$ of digits.
12. `unique_digit_count`: Count of unique digits (0–9).
13. `unique_digit_ratio`: Ratio of unique digits to total length.
14. `max_consecutive_repeated_digits`: Longest consecutive run of identical digits.
15. `repeated_digit_ratio`: Frequency of most common digit over length.
16. `sequential_digit_score`: Longest run of consecutive sequential ascending/descending digits.
17. `leading_zero_count`: Count of leading zero digits.
18. `country_match`: Binary match between requested country code and parsed region.

---

## 5. Model Training & Evaluation

Trained with `ml/training/train_phone_model.py` (`random_state=42`):

| Metric | Logistic Regression (L2) | Random Forest (100 Trees, Max Depth 10) |
|---|---|---|
| **Accuracy** | 99.76% | **100.00%** |
| **Precision** | 99.45% | **100.00%** |
| **Recall** | 100.00% | **100.00%** |
| **F1-Score** | 99.72% | **100.00%** |
| **ROC-AUC** | 1.0000 | **1.0000** |
| **False Positive Rate (FPR)** | 0.43% | **0.00%** |
| **False Negative Rate (FNR)** | 0.00% | **0.00%** |

* **Selected Model**: `Random_Forest` packaged into `ml/models/phone_model_v1.joblib` and synced to `backend/app/ml/models/phone_model_v1.joblib`.

---

## 6. Critical Telephony Limitations

1. **Caller ID Spoofing**: Attackers can spoof Caller ID (CLI) via VoIP trunks. Legitimate caller numbers can be spoofed by fraudsters without compromising the legitimate subscriber.
2. **Number Recycling**: Carriers routinely recycle inactive numbers within 90–180 days. A historic report does not permanently define a number's ownership.
3. **No Character/Identity Defamation**: The system analyzes *risk patterns* and *reported abuse records*. It does not assert the identity or personal moral character of any individual.
4. **Transparent Uncertainty**: The absence of fraud reports does **NOT** mean a phone number is safe. ScamBuster enforces explicit `UNKNOWN` classification when confidence is insufficient.
