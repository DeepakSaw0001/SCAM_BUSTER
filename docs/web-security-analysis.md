# ScamBuster — Phase 09: Malicious Website, Redirect & Download Risk Analysis

## Architectural Overview

ScamBuster Phase 09 extends ScamBuster's cybersecurity detection suite with safe, active outbound telemetry collection, redirect-chain tracking, HTML structure extraction, payload analysis, and APK cross-subsystem static analysis handoffs.

The subsystem operates under strict defensive boundaries: **it does not execute client-side JavaScript, never submits forms or credentials, and does not function as an open crawler or general web browser.**

```text
User URL
   │
   ▼
Existing URL Scanner (Phase 03 Static Lexical Engine)
   │
   ▼
Safe Web Fetcher (Centralized SSRF & DNS Rebinding Security Gate)
   │
   ├───────────────────────────────┐
   ▼                               ▼
HTTP & TLS Response Analyzer    Redirect Chain Analyzer
   │                               │
   └───────────────┬───────────────┘
                   ▼
       Safe Content & HTML Parser (No Execution)
                   │
    ┌──────────────┼────────────────────────┐
    ▼              ▼                        ▼
Downloads & MIME   Forms & Credential Inputs   External Scripts & iframes
    │              │                        │
    └──────────────┴───────────────┬────────┘
                                   ▼
                   Phase 07/08 APK Static Handoff (if APK detected)
                                   │
                                   ▼
                   Web Risk ML Classifier + Web Risk Rules
                                   │
                                   ▼
                   Unified Risk Engine Fusion (Lexical + Web + ML)
                                   │
                                   ▼
                   Correlated, Explainable Analysis Result
```

---

## 1. Safe Fetching & Resource Limits

All outbound HTTP operations are strictly constrained by immutable timeouts and resource boundaries configured in `backend/app/services/web_analysis/limits.py`:

- **Maximum Redirects:** 10 hops (`MAX_REDIRECTS`)
- **Maximum HTML Response Size:** 2 MB (`MAX_RESPONSE_SIZE`)
- **Maximum Download Payload Size:** 15 MB (`MAX_DOWNLOAD_SIZE`)
- **DNS Timeout:** 3.0s
- **Connect Timeout:** 5.0s
- **Read Timeout:** 8.0s
- **Total Scan Timeout:** 20.0s
- **Scanner User-Agent:** `ScamBusterSecurityScanner/1.0 (+https://scambuster.security; automated defensive security analysis)`

---

## 2. SSRF Protection & DNS Rebinding Defense

Outbound request safety is centralized in `backend/app/services/web_analysis/security_policy.py`. Prior to any socket connection or intermediate redirect hop, the system validates destination hostnames and resolves all associated IP addresses:

### Prohibited Networks
1. **Loopback:** `127.0.0.0/8`, `::1`
2. **Private IPv4 (RFC 1918):** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
3. **Link-Local & Cloud Metadata:** `169.254.0.0/16`, `fe80::/10`, `169.254.169.254`, `metadata.google.internal`
4. **Current / Broadcast / Multicast:** `0.0.0.0/8`, `224.0.0.0/4`, `255.255.255.255/32`
5. **Private IPv6:** `fc00::/7`
6. **Internal Domains:** `.local`, `.localhost`, `.internal`, `.lan`, `.corp`, `.home`, `.intranet`

### DNS Rebinding Protection
ScamBuster resolves domain names via `socket.getaddrinfo` and validates **every resolved address** against the prohibited networks list. If any resolved IP belongs to a forbidden subnet, the request is immediately aborted with `status: blocked` and a `CRITICAL` risk indicator is produced.

---

## 3. Redirect Chain Analysis

The `RedirectTracker` records every intermediate hop without exposing confidential credentials:
- **Redirection Methods:** HTTP 301, 302, 303, 307, 308, HTML `<meta http-equiv="refresh">`, and static script redirection patterns (`window.location = "..."`, `location.replace(...)`).
- **Cross-Domain Detection:** Uses two-part ccTLD-aware base domain parsing (`extract_registrable_domain`) to differentiate internal subdomain shifts from cross-domain transfers.
- **Domain Hopping:** Identifies rapid traversal across 3 or more distinct registered domains in a single chain.
- **Redirect Loops:** Detects circular redirection (A ➔ B ➔ A) and halts execution safely.
- **URL Shorteners:** Detects cloaking via common URL-shortening services (`bit.ly`, `tinyurl.com`, `t.co`, etc.).

---

## 4. HTML Content & Form Inspection

Implemented using Python's standard library `HTMLParser` (`SafeContentParser`) without client-side JavaScript execution:
- **Credential Harvesting Indicators:** Identifies forms requesting passwords, PINs, card numbers, CVVs, OTPs, or financial identifiers (UPI, routing numbers).
- **Transport Mismatch:** Flags credential forms served over unencrypted HTTP.
- **iframe Hierarchy:** Identifies hidden iframes (0x0 pixels, `display:none`) and cross-domain iframe embedding.
- **Static Script Obfuscation:** Detects patterns combining `eval`, `unescape`, and `fromCharCode`.

---

## 5. Download & Payload Detection

- **Download Triggers:** Evaluates `Content-Disposition: attachment`, binary MIME types (`application/vnd.android.package-archive`, `application/x-msdownload`, `application/octet-stream`), and dangerous file extensions.
- **Magic Byte Verification:** Inspects binary headers (`PK\x03\x04` for APK/ZIP, `MZ` for PE executables, `%PDF` for documents).
- **Cryptographic Hashes:** Calculates SHA-256, SHA-1, and MD5 for deduplication and reputation tracking.

---

## 6. APK Handoff Integration (Phase 07 & 08 Reuse)

When an Android package (`.apk`) is safely identified:
1. The payload snippet is streamed up to `MAX_DOWNLOAD_SIZE` into a secure temporary file.
2. The file is passed to Phase 07 (`analyze_apk_file`) and Phase 08 (`analyze_apk_permissions`, `evaluate_apk_privacy_rules`).
3. Extracted findings (Package Name, Target SDK, Sensitive Permissions, Privacy Risk Score, High-Impact Capabilities) are embedded into the scan response.
4. **Code is never installed or executed.**

---

## 7. Machine Learning Subsystem

- **Feature Vector:** 24 numerical metrics spanning redirect behavior, security headers, credential inputs, iframes, and file downloads.
- **Training Dataset:** 1,250 balanced samples across `benign`, `suspicious`, `phishing`, and `malicious` profiles.
- **Zero Data Leakage:** GroupShuffleSplit grouped by base domain guarantees zero overlap between training and test sets.
- **Evaluated Models:** Logistic Regression vs Random Forest Classifier.
- **Selected Model:** Logistic Regression (`F1 = 1.0000`, `Accuracy = 1.0000`, `ROC-AUC = 0.7950`).

---

## 8. Threat Intelligence Abstraction

`FileHashIntelligenceService` provides a modular lookup architecture for SHA-256 file hashes. When external API keys are omitted, the provider explicitly reports `status: "not_configured"`, adhering to the strict anti-fabrication mandate.

---

## 9. Privacy & Redaction

- Sensitive tokens in query parameters (`token=...`, `key=...`, `password=...`) are automatically redacted in logs and chain visualizations.
- Cookie headers and user session tokens are strictly discarded.
- Raw HTML bodies are never permanently retained in the database.

---

## 10. Technical Limitations

> [!IMPORTANT]
> **Static and Non-Interactive Limitations:**
> 1. Static website analysis does not execute client-side JavaScript frameworks or client-rendered single page application (SPA) state changes.
> 2. The scanner does not submit credentials, solve CAPTCHAs, or authenticate to private portals.
> 3. Presence of an executable or APK download indicates capability, not definitive malware proof, unless verified by heuristic or signature engines.
> 4. Absence of threats does not guarantee benevolence.
