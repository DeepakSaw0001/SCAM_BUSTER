# ScamBuster — Android APK Static Security & Malware Analysis Architecture (Phase 07)

## 1. Executive Architecture

ScamBuster Phase 07 implements a zero-execution, multi-layered static analysis pipeline designed to audit untrusted Android Package (`.apk`) files. The subsystem operates exclusively on static archive structures, AXML manifests, DEX bytecode strings, and digital signature blocks.

```text
                                 Untrusted APK Upload
                                          │
                    ┌─────────────────────▼─────────────────────┐
                    │       Secure File & Archive Validation    │
                    │ - Max 50MB raw limit                       │
                    │ - Path traversal rejection (.., /, \)     │
                    │ - ZIP-bomb & decompression ratio limit     │
                    │ - Max 15,000 file entries                  │
                    └─────────────────────┬─────────────────────┘
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │                Static Extraction          │
                    ├────────────────────────┬──────────────────┤
                    │ AndroidManifest.xml    │ classes.dex      │
                    │ (pyaxmlparser)         │ (Regex/Bytecode) │
                    ├────────────────────────┼──────────────────┤
                    │ lib/*.so (Native ABIs) │ META-INF/*.RSA   │
                    │ (ELF headers)          │ (asn1crypto DER) │
                    └─────────────────────┬──┴──────────────────┘
                                          │
            ┌─────────────────────────────┼─────────────────────────────┐
            │                             │                             │
            ▼                             ▼                             ▼
    Permission Taxonomy            DEX Bytecode Scan           Offline URL Scoring
  - AOSP Dangerous Tiers        - Dynamic code loading       - Phase 03 Static Engine
  - Banking Trojan Overlays     - Reflection & execve        - Zero external HTTP hits
  - Spyware Surveillance        - Root / su / sh strings
            │                             │                             │
            └─────────────────────────────┼─────────────────────────────┘
                                          │
                               ┌──────────┴──────────┐
                               │ Feature Vector v1   │
                               │ (26 dimensions)     │
                               └──────────┬──────────┘
                                          │
                       ┌──────────────────┴──────────────────┐
                       ▼                                     ▼
             Static Rule Engine                       Random Forest ML
        - Heuristic indicators                   - 100-tree ensemble
        - AOSP privilege abuse                   - Confidence scoring
                       │                                     │
                       └──────────────────┬──────────────────┘
                                          │
                                          ▼
                                Threat Intelligence
                             - SHA-256 hash lookup
                             - 300s TTL in-memory cache
                             - Status 'not_configured' fallback
                                          │
                                          ▼
                                Unified Risk Engine
                             - Defense-in-depth floors
                             - Multi-evidence deduplication
                             - Calibrated tiers: LOW / MEDIUM / HIGH / CRITICAL
                                          │
                                          ▼
                             Explainable Analysis Report
```

---

## 2. Secure Upload & Archive Ingestion Controls
Every uploaded file is treated as hostile input.

* **Size Caps:** Hard limits of 50 MB on uploaded archives (`MAX_APK_SIZE`) and 250 MB on cumulative uncompressed content (`MAX_UNCOMPRESSED_SIZE`).
* **Path Traversal Defense:** Absolute paths, Windows drive letters (`C:`), leading slashes, and relative directory traversals (`../`) within archive entry headers trigger immediate rejection.
* **ZIP Bomb & Compression Ratio Defense:** Archives exceeding a compression ratio of 25.0x on entries greater than 20 KB are rejected to thwart compression-based denial of service.
* **Immediate Ephemeral Cleanup:** Uploaded files are written with random UUID prefixes (`scambuster_<uuid>.apk`) to the OS temporary directory and guaranteed to be purged in a `finally` block upon scan completion.
* **ZERO Runtime Execution:** ScamBuster never calls `adb`, never installs the package, never boots an emulator, and never invokes native `.so` binaries.

---

## 3. AndroidManifest & Component Analysis
Using pure-Python binary AXML decoding (`pyaxmlparser`), the system extracts:
1. **Package Identifiers:** Package name, version code, version name, `minSdkVersion`, and `targetSdkVersion`.
2. **Component Manifest:** Declared Activities, Services, Broadcast Receivers, and Content Providers.
3. **Exported Attack Surface:** Counts components flagged `exported="true"`, identifying exposure vectors accessible to other unprivileged applications on device.

---

## 4. Permission Taxonomy & Contextual Risk
Permissions are classified using official Android Open Source Project (AOSP) protection tiers:
* `NORMAL`: Zero user prompt required (e.g. `INTERNET`, `ACCESS_NETWORK_STATE`, `VIBRATE`).
* `DANGEROUS`: Requires explicit runtime approval (e.g. `READ_SMS`, `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`).
* `SPECIAL`: System-level capabilities (e.g. `SYSTEM_ALERT_WINDOW`, `BIND_ACCESSIBILITY_SERVICE`, `REQUEST_INSTALL_PACKAGES`, `BIND_DEVICE_ADMIN`).

### High-Interest Threat Clusters
Rather than penalizing individual legitimate permissions (e.g., Camera in a video conferencing app), the analyzer evaluates co-occurring capability clusters:
1. **Banking Trojan Cluster:** `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` (+ `SMS` / `INTERNET`). Characteristic of overlay trojans (Anatsa, SharkBot) intercepting credentials and 2FA SMS tokens.
2. **Spyware / Surveillance Cluster:** `CAMERA` + `RECORD_AUDIO` + `ACCESS_FINE_LOCATION` + `READ_CONTACTS` + `INTERNET`. Simultaneous background audio/visual capture and contacts exfiltration.
3. **Secondary Dropper Cluster:** `REQUEST_INSTALL_PACKAGES` + `INTERNET`. Enables unverified third-party APK payload downloading outside of the Google Play Store ecosystem.
4. **Device Administrator Lockout:** `BIND_DEVICE_ADMIN`. Grants privileges that can prevent uninstallation or initiate remote lockouts.

---

## 5. Dalvik Executable (DEX) Static Code Analysis
Without launching Dalvik or ART runtimes, bytecode files (`classes.dex`, `classes2.dex`) are parsed statically for high-risk API invocation signatures:
* **Dynamic Code Loading:** References to `DexClassLoader`, `PathClassLoader`, or `InMemoryDexClassLoader` (indicates secondary payload execution or packed routines).
* **Reflection Invocations:** References to `java/lang/reflect/Method;->invoke` or `java/lang/Class;->forName`.
* **Root / Shell Execution:** Invocations of `/system/bin/sh`, `/system/xbin/su`, `Runtime.exec`, or `ProcessBuilder`.
* **Telephony & SMS APIs:** Direct calls to `SmsManager.sendTextMessage` or telephony background dispatches.

---

## 6. Native Libraries & Digital Certificates
* **Native Library Inspection:** Scans `lib/<abi>/*.so` entries to identify architecture targets (`arm64-v8a`, `armeabi-v7a`, `x86_64`) and embedded shared objects.
* **X.509 Certificate Analysis:** Parses DER/PKCS#7 signature blocks in `META-INF/*.RSA` via `asn1crypto` to extract X.509 Subject, Issuer, Validity periods, and SHA-256 fingerprint. Detects default Android Debug keystore signatures (`CN=Android Debug`).

---

## 7. Embedded URLs & Static Network Indicators
* **Static URL Extraction:** Regex extraction of HTTP/HTTPS URLs embedded in DEX string tables.
* **Benign Filtering:** Automatically suppresses Android/W3C schema namespaces (`schemas.android.com`, `www.w3.org`).
* **Zero Outbound Contact:** Extracted URLs are scored strictly offline through ScamBuster's Phase 03 static URL heuristic rule analyzer. The backend makes ZERO outbound HTTP/DNS requests to embedded endpoints.

---

## 8. Threat Intelligence Architecture
An extensible provider abstraction (`ApkIntelligenceProvider`) supports privacy-preserving reputation lookups:
* **SHA-256 Querying:** Lookups are conducted strictly by cryptographic file hash, never by transmitting APK binary content to external providers.
* **In-Memory TTL Caching:** Query results are cached for 300 seconds to prevent redundant network round-trips.
* **Graceful Degradation:** When no provider credentials are configured, the service returns status `not_configured` without failing the scan or reporting synthetic indicators.

---

## 9. Security Limitations
1. **No Dynamic Emulation:** Runtime evasions such as emulator detection, delayed payload execution (e.g. sleep for 72 hours), or encrypted C2 traffic require future sandbox execution phases.
2. **Commercial Code Obfuscators:** Extreme commercial packers (e.g. SecNeo, Bangcle) that dynamically decrypt DEX bytecodes in native `.so` memory are reported as high-risk anomalies based on native/dynamic indicators rather than inner DEX method traces.
3. **No Root Exploitation Analysis:** The system identifies privilege escalation strings (`su`, `sh`) but does not attempt to execute or verify exploit payloads.
