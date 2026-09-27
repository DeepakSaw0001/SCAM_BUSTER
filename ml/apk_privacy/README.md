# ScamBuster ML — APK Privacy Risk Model (Phase 08)

## 1. Overview & Objective

The APK Privacy Risk Model predicts the **privacy-risk tier** (`low`, `medium`, `high`, `critical`) of an Android application package based strictly on extracted static capability features, permission counts, multi-permission combination attack surfaces, bytecode API correlations, and contextual category mismatch scores.

### Key Distinction
The model targets **privacy risk attention level**, NOT malware classification:
* A legitimate, popular social networking application or video conferencing app may naturally warrant a `high` privacy risk tier due to broad camera, audio, location, and contact access.
* The model is evaluated separately from the APK malware classifier (`apk_malware_model_v1.joblib`).

---

## 2. Dataset

* **Source**: Curated AOSP Permission & Capability Benchmark Corpus (`ml/datasets/processed/apk_privacy_corpus.csv`)
* **Collection / Generation Date**: 2026-09-26
* **Sample Count**: 2,400 documented Android package profiles across 15 distinct functional application categories
* **Class Distribution**:
  - `low`: 600 samples (25.0%)
  - `medium`: 600 samples (25.0%)
  - `high`: 600 samples (25.0%)
  - `critical`: 600 samples (25.0%)
* **Leakage Prevention**: Stratified train/test partition (80% train / 20% test). Feature scaling fitted strictly on the training partition.

---

## 3. Feature Engineering (`privacy-feature-v1`)

The model uses 16 deterministic static capability features extracted from Android packages:

| Feature Name | Type | Description |
|---|---|---|
| `permission_count` | int | Total number of permissions declared in AndroidManifest.xml |
| `sensitive_permission_count` | int | Count of permissions in HIGH or VERY_HIGH sensitivity tiers |
| `high_impact_permission_count` | int | Count of elevated capabilities (Accessibility, Device Admin, Overlay, SMS) |
| `permission_category_count` | int | Number of unique functional categories spanned |
| `permission_combination_count` | int | Count of multi-permission attack surface clusters detected |
| `api_permission_match_count` | int | Count of declared permissions corroborated by bytecode API references |
| `context_mismatch_score` | int (0-100) | Penalty reflecting anomalous permissions relative to declared category |
| `exported_component_count` | int | Number of exported activities, services, and receivers |
| `service_count` | int | Number of declared background services |
| `receiver_count` | int | Number of declared broadcast receivers |
| `has_accessibility_indicator` | binary (0/1) | Whether BIND_ACCESSIBILITY_SERVICE is requested |
| `has_overlay_indicator` | binary (0/1) | Whether SYSTEM_ALERT_WINDOW is requested |
| `has_device_admin_indicator` | binary (0/1) | Whether BIND_DEVICE_ADMIN is requested |
| `has_boot_autostart_indicator` | binary (0/1) | Whether RECEIVE_BOOT_COMPLETED is requested |
| `has_sms_capability` | binary (0/1) | Whether SMS transmission/reception capabilities are requested |
| `has_location_capability` | binary (0/1) | Whether GPS or network location capabilities are requested |

---

## 4. Models Evaluated & Selection

Two candidate architectures were trained and evaluated on 480 test samples:

| Model Architecture | Test Accuracy | Macro Precision | Macro Recall | Macro F1 | Weighted F1 |
|---|---|---|---|---|---|
| **Logistic Regression** (Multinomial, C=1.0) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |
| **Random Forest** (n_estimators=100) | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 1.0000 |

### Selected Model
**Logistic Regression** (Pipeline with `StandardScaler`) was selected as the primary production model due to its ultra-fast inference latency (< 1ms), linear explainability, and minimal memory footprint.

* **Artifact Path**: `ml/models/apk_privacy_model_v1.joblib`
* **Backend Synced Path**: `backend/app/ml/models/apk_privacy_model_v1.joblib`
* **Metadata**: `backend/app/ml/models/apk_privacy_model_v1_metadata.json`

---

## 5. Limitations

1. **Static Inference Only**: Features are derived exclusively from static package declarations and bytecode string tables.
2. **Context Dependency**: If application category is unspecified, the context mismatch score defaults to 0 to prevent artificial inflation.
3. **No Dynamic Execution**: The ML pipeline does not execute or sandbox the APK.
