# ScamBuster Threat Intelligence Baseline Dataset & Provenance Documentation

## 1. Overview & Data Engineering Governance

This dataset directory documents curated security indicator feeds utilized by ScamBuster's Threat Intelligence & Reputation Correlation Layer (Phase 11).

Threat intelligence indicators are treated strictly as **EVIDENCE** rather than ground truth or deterministic classification targets.

---

## 2. Dataset Metadata & Provenance

* **Dataset Name**: `scambuster_threat_intel_baseline_v1`
* **Version**: `2026.09.v1`
* **Collection / Curation Date**: September 26, 2026
* **Curator**: ScamBuster Threat Intelligence & Cybersecurity Engineering Group
* **License**: **Open Database License (ODbL) v1.0** / Public Domain Security Research Benchmarks
* **Indicator Types Supported**:
  * `DOMAIN`: Registered domains and fully qualified hostnames
  * `URL`: Fully normalized URLs with path and query parameters
  * `IP`: IPv4 and IPv6 canonical representations (RFC 1918 / Bogon filtered)
  * `FILE_HASH`: SHA-256 (primary), SHA-1, MD5
  * `PHONE`: E.164 normalized international telephone numbers
  * `EMAIL`: Normalized sender domains and privacy-hashed email addresses

---

## 3. Strict ML Data Leakage Controls (Section 55 & 56)

### The Data Leakage Problem
In cybersecurity machine learning, a critical pitfall is **label leakage** (or target leakage), where an external reputation label (e.g., `provider_verdict == "malicious"`) is fed as a feature into an ML model whose target is predicting whether that identical indicator is malicious.
If an ML model learns `if provider_is_malicious: predict malicious`, the model simply memorizes the provider label. When the provider is offline or encountering novel, zero-day attacks, the ML model collapses.

### ScamBuster's Leakage Mitigation Architecture
1. **Target Independence**: ML models (URL Random Forest classifier, Email/SMS TF-IDF + Logistic Regression, APK Permission Classifier) are trained purely on **intrinsic, structural, and lexical features**:
   * Lexical features: URL length, entropy, digit ratio, token counts, subdomains.
   * Content features: Anchor text vs HREF mismatch, form actions, credential harvesting keywords, TF-IDF n-grams.
   * Static bytecode features: Android manifest permissions, intent filters, reflection, dynamic DEX loading.
2. **Post-ML Risk Engine Correlation**: Threat intelligence reports are evaluated downstream by the unified **Risk Engine** (`UnifiedScorer`) as independent evidence signals alongside rule findings and ML probabilities:
   ```text
   Lexical Rules finding (Static)
   + ML Probability (Structural / NLP / Static APK)
   + Threat Intelligence Reports (Multi-source Provenance)
   ─────────────────────────────────────────────────────────────
   = Unified Explainable Risk Assessment
   ```
3. **No Target Leakage in Training Pipelines**: Threat intelligence reputation scores and verdicts are strictly quarantined from ML training vectors.

---

## 4. Deduplication & Sanitization Pipeline

1. **Standardized Normalization**:
   * Domains: Lowercase, trailing dot stripped, Punycode/IDN decoded, registrable domain extracted via Public Suffix List rules.
   * URLs: Lowercase scheme and host, default ports (80/443) stripped, query parameter keys sorted, fragments removed.
   * IPs: Canonicalized via `ipaddress.ip_address`. Private, loopback, link-local, multicast, and bogon addresses flagged (`is_private_or_bogon = True`) to prevent SSRF.
   * Hashes: Lowercase hex representation, strictly 64 characters for SHA-256.
   * Phone: Normalized to E.164 standard reusing ScamBuster's telecom normalizer.
2. **Duplicate Detection & Rejection**:
   * Duplicate records within feed updates are rejected automatically (`duplicates_rejected` counter tracked).
   * In-flight duplicate requests are collapsed using per-indicator asyncio locks (`_inflight_locks`).
3. **Privacy Hashing**:
   * In-memory cache indexes entries using `sha256(type + ":" + normalized_value)`.
   * Passwords, OTPs, session cookies, authorization headers, and raw message contents are strictly excluded from queries and caches.

---

## 5. Feed Versioning & Rollback Safety

The local threat feed catalog implements immutable versioning:
* Active feed version: `2026.09.v1`
* Previous snapshot retained in memory: `_previous_records`
* Rollback capability: Calling `catalog.rollback()` instantaneously restores the prior verified state with atomic lock safety if a corrupted or unverified feed update is received.

---

## 6. Limitations

1. **Coverage**: Local feeds represent known, verified malicious infrastructure (Cerberus, FluBot, SharkBot, SpyNote APK hashes; high-volume credential harvesting domains; Wangiri telecom numbers). Zero-day domains will not match known feed lists.
2. **Temporal Decay**: Attack infrastructure is ephemeral (fast-flux DNS, disposable domains). Intelligence entries carry freshness markers (`checked_at`, `data_age_seconds`) and short cache TTLs (30m to 12h) to avoid stale verdicts.
3. **Unknown State**: An unlisted indicator evaluates as `UNKNOWN`, which is never interpreted as `SAFE` or `MALICIOUS`.
