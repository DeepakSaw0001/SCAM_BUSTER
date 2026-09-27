# ScamBuster ML — Android APK Malware & Trojan Dataset Documentation (Phase 07)

## 1. Dataset Overview

* **Dataset Name**: ScamBuster Android APK Security & Malware Benchmark Corpus (v1.0)
* **Primary Reference Benchmarks**:
  * **Canadian Institute for Cybersecurity (CIC) Android Malware Dataset (CIC-InvesAndMal2019 / CICMalAnal2017)**:
    * Standard academic Android malware benchmark covering Banking Trojans, Adware, Ransomware, and Scareware.
    * Source: University of New Brunswick (UNB) / CIC Open Research Datasets
    * License: Academic Research & Cybersecurity Education License
  * **Drebin Android Malware Dataset / AndroZoo Open Academic Benchmark**:
    * Large-scale feature distributions from verified benign Google Play Store packages and historical analyzed malware samples.
* **Collection Method**: Static feature extraction and metadata compilation (zero runtime/dynamic execution).
* **Sample Count**: 3,600 unique, deduplicated APK feature profiles:
  * Benign Applications (`0`): 2,000 (Standard utilities, calculators, enterprise tools, media players from clean Google Play distributions)
  * Malicious Applications (`1`): 1,600 (Banking Trojans [Anatsa, SharkBot, Teabot], SMS Toll Fraud, Droppers, Spyware)
* **Acquisition Date**: September 2026

---

## 2. Safety & Handling Protocol

In accordance with ScamBuster Phase 07 strict security requirements:
* **Zero Live Malware Execution**: No live malware samples or APKs were executed, installed, or launched during training or evaluation.
* **Feature Representation**: Models are trained exclusively on static structural, permission, component, and bytecode API frequency features.
* **Zero Leaked / Private Data**: No private user devices or confidential proprietary applications were included.

---

## 3. Data Leakage Prevention

* **Deduplication by Package & Signature**: Multiple repackaged variants or minor version updates of the same application were collapsed into unique feature representations to prevent family memorization.
* **Stratified Splitting**: 80% Train / 20% Test stratified split performed strictly after deduplication so that no identical feature fingerprints bridge the split.
* **Preprocessing Isolation**: Scaling and normalization parameters are fitted exclusively on the training partition.

---

## 4. Fundamental Limitations of Static APK Analysis

1. **Obfuscation & Packing**: Advanced commercial packers (e.g., DexGuard, SecNeo) and encrypted payload droppers conceal manifest strings and bytecode until runtime memory loading.
2. **Evolving Permission Models**: Newer Android versions (Android 13/14+) use scoped storage and granular media permissions, altering feature distributions over time.
3. **Contextual Ambiguity**: Legitimate remote-support or enterprise MDM tools may legitimately request Device Admin or Accessibility services. ML output is a probabilistic signal, not an absolute proof of intent.
