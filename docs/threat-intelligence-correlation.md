# ScamBuster — Threat Intelligence & Reputation Correlation Architecture (Phase 11)

## Executive Summary

Phase 11 transforms ScamBuster from isolated, point-in-time scanning engines into a **connected, multi-source cyber threat intelligence and reputation correlation platform**.

The layer operates under foundational cybersecurity principles:
1. **Intelligence is Evidence, Not Inviolable Truth**: Provider verdicts are treated as independent pieces of corroborating evidence. The unified Risk Engine synthesizes reputation signals alongside intrinsic lexical, structural, and behavioral ML evaluations.
2. **UNKNOWN $\neq$ SAFE**: The absence of reputation data in a feed or third-party database never indicates benign status.
3. **Transparent Conflict Preservation**: When external reputation sources disagree (e.g., Provider A flags malicious while Provider B reports clean), the conflict is explicitly presented and explained to the analyst, never hidden or averaged out.
4. **Offline Resilience**: ScamBuster functions autonomously without internet connectivity or external API dependencies using a curated, versioned local threat feed catalog.
5. **Zero User Content Leakage**: Raw message bodies, passwords, OTPs, session cookies, and authorization headers are never transmitted to external services or cached.

---

## Architecture Flow

```text
                  ScamBuster Scan Target
               (URL / Email / SMS / APK / Phone)
                            │
                            ▼
                  Indicator Extraction
            (URL, Domain, IP, Hash, Phone, Email)
                            │
                            ▼
                  Standard Normalizer
            (Punycode, Lowercase, E.164, SHA-256)
                            │
                            ▼
                Privacy-Preserving Cache
                 [SHA-256 Key Partition]
                   │                │
            HIT    │                │  MISS
         ┌─────────┘                └────────┐
         ▼                                   ▼
   Cached Evidence                   Providers & Feeds
   (Freshness: CACHED)        ┌──────────────┴──────────────┐
                              ▼                             ▼
                    Local Feed Catalog            External REST Adapters
                    (ODbL Curated Intel)          (SSRF-Guarded, Rate-Limited)
                              │                             │
                              └──────────────┬──────────────┘
                                             │
                                             ▼
                               Multi-Source Correlation
                             (Budget Cap, Corroboration,
                              Conflict Detection, Graph)
                                             │
                                             ▼
                                    Unified Risk Engine
                             (Explainable Evidence Fusion)
                                             │
                                             ▼
                                  Frontend Scan Result
```

---

## 1. Indicator Model & Normalization

All indicators across the platform are normalized through `app.intelligence.normalizer.normalize_indicator()`:

| Indicator Type | Normalization Policy | Special Security Handling |
| :--- | :--- | :--- |
| **`DOMAIN`** | Lowercase, strip trailing dots, Punycode/IDN decoded, registrable domain extracted. | Homoglyph & IDN spoof detection. |
| **`URL`** | Lowercase scheme/host, drop default ports (80/443), sort query keys, strip fragment. | Trailing slash collapse, path traversal sanitization. |
| **`IP`** | Canonical representation via Python `ipaddress`. | RFC 1918 private, loopback, link-local, multicast, bogon detected & flagged to block SSRF. |
| **`FILE_HASH`** | Lowercase hex string, length validation (64 for SHA-256). | SHA-256 primary, legacy SHA-1/MD5 accepted with lowercase. |
| **`PHONE`** | E.164 international standard (`+<country_code><number>`). | Reuses existing telecom normalizer. |
| **`EMAIL`** | Lowercase, trimmed, domain extracted. | Email prefix privacy-masked (`j***@domain.com`). |

---

## 2. Privacy-Preserving Cache (`IntelligenceCache`)

The cache optimizes latency and prevents unnecessary external API calls while upholding strict user privacy:

- **Key Derivation**: `SHA-256(indicator_type + ":" + normalized_value)`.
- **In-Flight Collapsing**: Per-indicator `asyncio.Lock()` instances collapse concurrent identical requests into a single lookup.
- **Configurable TTL Policy**:
  - `FILE_HASH`: 12 hours (43,200s) — malware binaries are immutable.
  - `DOMAIN`: 4 hours (14,400s) — domain reputation evolves moderately.
  - `URL`: 1 hour (3,600s) — phishing paths change rapidly.
  - `IP`: 2 hours (7,200s) — dynamic hosting & cloud IPs rotate.
  - `PHONE`: 6 hours (21,600s) — scam caller numbers persist across campaigns.
- **Bounded Eviction**: FIFO eviction when capacity reaches `MAX_CACHE_ENTRIES` (default: 5,000).
- **Telemetry**: Hit rate, request count, cache hits, misses, and evictions tracked via `/scan/intelligence/status`.

---

## 3. Provider Abstraction & Adapters

Every intelligence source inherits from `BaseThreatIntelligenceProvider`:

1. **`LocalFeedThreatProvider`** (Priority: 10):
   - Consults `LocalFeedCatalog` in memory.
   - Zero network latency (<1ms), 100% offline uptime, zero cost.
2. **`OpenThreatProvider`** (Priority: 50):
   - Safe HTTP REST client for public / commercial threat intelligence APIs.
   - Guarded by SSRF checks (blocks private IPs, localhost, AWS metadata `169.254.169.254`).
   - Caps inbound payload size to 512 KB to prevent decompression/memory bombing.
3. **`MockThreatIntelProvider`** (Priority: 99):
   - Deterministic testing harness with failure injection (timeouts, HTTP 429 rate limit, HTTP 500 server error, malformed JSON).

### Rate Limiting & Resilience
- **Sliding-Window Rate Limiter**: Enforces strict request-per-minute quotas per provider.
- **Exponential Backoff**: Up to `max_retries` (default: 2) with bounded jittered backoff.
- **Timeout Isolation**: Default 3.0s timeout per external request. Slow providers never block the main ScamBuster scan pipeline.

---

## 4. Multi-Source Corroboration & Conflict Preservation

The `ThreatIntelligenceCorrelator`:
- Evaluates reports across all consulted providers.
- Flags **`is_corroborated = True`** when $\ge 2$ independent sources report the same high-severity verdict (`MALICIOUS` or `SUSPICIOUS`).
- Flags **`has_conflicts = True`** when one provider reports `MALICIOUS` while another reports `BENIGN` or `SAFE`.
- **Conflict Handling Policy**: In the event of a conflict, the Risk Engine preserves all reports, elevates the alert level to safety-first precedence, and generates transparent explainability text:
  > *"External intelligence sources disagree on this indicator. Preserved source verdicts: [Source A: Malicious, Source B: Benign]. The Risk Engine evaluates this under safety-first precedence."*

---

## 5. Threat Relationship Graph (`ThreatGraph`)

The correlation engine builds an indicator relationship graph linking connected attack artifacts:

```text
    Target: https://cdn-updates.xyz/login/setup.apk
                   │
                   ├── [RESOLVES_TO] ──► 198.51.100.24 (IP)
                   ├── [DOWNLOADS_FILE] ──► e3b0c442... (APK SHA-256)
                   └── [CALLS_PHONE] ──► +18005550199 (Support Callback)
```

The frontend renders this graph with color-coded risk nodes and relational link cards.

---

## 6. Risk Engine Integration

Threat intelligence integrates into `UnifiedScorer` across all input modalities:
- **URL Scans**: Correlated domain and URL indicators elevate risk score when corroborated malicious indicators are discovered.
- **Email Scans**: Sender domain, embedded hyperlinks, and attachment file hashes are correlated.
- **SMS / Message Scans**: Extracted URLs and telecom sender numbers are correlated.
- **APK Scans**: APK file SHA-256 and signing certificate fingerprints are correlated against known mobile trojan signatures (FluBot, Cerberus, SharkBot, SpyNote).
- **Phone Scans**: Carrier number and international format are cross-referenced with telecommunication fraud registries.

---

## 7. Security Controls

- **No Secrets in Source**: API keys configure strictly through environment variables (`THREAT_INTEL_API_KEY`).
- **No Secrets in Responses**: `/scan/intelligence/status` redacts all credentials and tokens.
- **SSRF Defense**: External HTTP adapters reject attempts to query RFC 1918 addresses, loopbacks, link-local, and cloud metadata.
- **Input Sanitization**: Indicators are stripped of control characters, HTML tags, and null bytes prior to processing.
- **Resource Protection**: Scan-level budget caps (`MAX_PROVIDER_REQUESTS_PER_SCAN = 10`) prevent malicious inputs from abusing ScamBuster as a free proxy.
