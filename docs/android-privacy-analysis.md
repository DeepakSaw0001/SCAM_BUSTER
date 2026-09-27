# Android Permission & Privacy Risk Analysis (Phase 08)

## 1. Overview & Core Philosophy

ScamBuster Phase 08 introduces dedicated, context-aware static permission auditing and privacy risk analysis for Android applications.

### Fundamental Principles

```text
PERMISSION REQUESTED ≠ MALICIOUS APPLICATION
SENSITIVE PERMISSION ≠ AUTOMATIC PRIVACY VIOLATION
STATIC BYTECODE API REFERENCE ≠ PROOF OF RUNTIME ACCESS
```

A video-conferencing application legitimately requests `CAMERA` and `RECORD_AUDIO`. Conversely, a simple flashlight or calculator application requesting `READ_SMS`, `READ_CONTACTS`, `CAMERA`, and `RECORD_AUDIO` presents significant contextual mismatch and excessive privilege exposure.

ScamBuster measures:
> **The degree of privacy/security attention warranted by the observed application capabilities.**

It does **NOT** compute a malware probability when calculating privacy risk. Privacy risk and malware risk are distinct orthogonal dimensions that feed into the unified Risk Engine.

---

## 2. Centralized Permission Taxonomy

All permission definitions, functional categories, and risk semantics are centralized in:
`backend/app/security/android_permissions/`

### Directory Structure
```text
backend/app/security/android_permissions/
├── __init__.py          # Unified exports
├── catalog.py           # 80+ authoritative AOSP permission metadata records
├── categories.py        # Functional categories and sensitivity levels
├── version.py           # Android API level milestones and version awareness
├── api_mapping.py       # Static Dalvik bytecode / DEX API signatures
└── risk_rules.py        # Multi-permission combinations & context expectations
```

### Functional Categories
* `IDENTITY`: Account enumeration and profile identifiers (`GET_ACCOUNTS`)
* `CONTACTS`: Contact books and personal address graphs (`READ_CONTACTS`, `WRITE_CONTACTS`)
* `PHONE`: Telephony state, IMEI/IMSI access, call placing (`READ_PHONE_STATE`, `CALL_PHONE`, `READ_CALL_LOG`)
* `SMS`: Inbound/outbound SMS, OTP codes, MMS (`READ_SMS`, `RECEIVE_SMS`, `SEND_SMS`)
* `LOCATION`: Fine GPS, coarse network, background tracking (`ACCESS_FINE_LOCATION`, `ACCESS_BACKGROUND_LOCATION`)
* `CAMERA`: Camera capture and visual data streaming (`CAMERA`)
* `MICROPHONE`: Audio recording and ambient room capture (`RECORD_AUDIO`)
* `STORAGE_FILES`: Shared external file system access (`READ_EXTERNAL_STORAGE`, `MANAGE_EXTERNAL_STORAGE`)
* `MEDIA`: Granular Android 13+ media access (`READ_MEDIA_IMAGES`, `READ_MEDIA_VIDEO`, `READ_MEDIA_AUDIO`)
* `CALENDAR`: User scheduling and calendar events (`READ_CALENDAR`, `WRITE_CALENDAR`)
* `SENSORS`: Biometric and physiological monitoring (`BODY_SENSORS`, `ACTIVITY_RECOGNITION`)
* `BLUETOOTH`: Proximity scanning and peripheral connections (`BLUETOOTH_SCAN`, `BLUETOOTH_CONNECT`)
* `NETWORK`: Sockets and network interfaces (`INTERNET`, `ACCESS_NETWORK_STATE`)
* `NOTIFICATIONS`: Notification listening and dispatch (`POST_NOTIFICATIONS`, `BIND_NOTIFICATION_LISTENER_SERVICE`)
* `ACCESSIBILITY`: Deep UI tree inspection and input injection (`BIND_ACCESSIBILITY_SERVICE`)
* `OVERLAY`: Drawing windows over other running apps (`SYSTEM_ALERT_WINDOW`)
* `DEVICE_ADMIN`: Enterprise device control policies (`BIND_DEVICE_ADMIN`)
* `INSTALLATION`: Dropping and installing secondary APK packages (`REQUEST_INSTALL_PACKAGES`)
* `SYSTEM_CONTROL`: Low-level system control and persistence (`RECEIVE_BOOT_COMPLETED`, `PACKAGE_USAGE_STATS`)
* `UNKNOWN`: Unrecognized custom or vendor-defined permissions

### Sensitivity Tiers
1. **LOW**: Minimal privacy impact; standard utility (e.g. `VIBRATE`, `ACCESS_NETWORK_STATE`, `INTERNET`).
2. **MEDIUM**: Contextual data access requiring care (e.g. `ACCESS_COARSE_LOCATION`, `BLUETOOTH_CONNECT`).
3. **HIGH**: Direct access to user environment or persistent tracking (e.g. `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE_LOCATION`, `READ_CONTACTS`).
4. **VERY_HIGH**: Capabilities capable of intercepting 2FA OTPs, total device takeover, or UI hijacking (e.g. `READ_SMS`, `BIND_ACCESSIBILITY_SERVICE`, `SYSTEM_ALERT_WINDOW`, `BIND_DEVICE_ADMIN`, `ACCESS_BACKGROUND_LOCATION`).

---

## 3. Android Version Awareness

Permission behavior depends strictly on target and running Android API levels:

| Milestone | API Level | Privacy & Security Evolution |
|---|---|---|
| **Android 6.0 (Marshmallow)** | API 23 | Runtime permission prompts introduced for `dangerous` permissions. |
| **Android 10 (Q)** | API 29 | Background location isolated into `ACCESS_BACKGROUND_LOCATION`. |
| **Android 11 (R)** | API 30 | Scoped Storage strictly enforced; `MANAGE_EXTERNAL_STORAGE` introduced. |
| **Android 12 (S)** | API 31 | Runtime `BLUETOOTH_SCAN` decoupled from Location; approximate location option. |
| **Android 13 (Tiramisu)** | API 33 | `POST_NOTIFICATIONS` runtime prompt; `READ_EXTERNAL_STORAGE` deprecated in favor of granular `READ_MEDIA_*`. |
| **Android 14 (UpsideDownCake)** | API 34 | User-selected media access (`READ_MEDIA_VISUAL_USER_SELECTED`). |

ScamBuster inspects `targetSdkVersion` to apply correct semantic rules (e.g., distinguishing whether `READ_EXTERNAL_STORAGE` grants broad storage on Android 10 or is ineffective on Android 14).

---

## 4. Multi-Permission Capability Combinations

Privileges in combination often create security risks beyond the sum of individual declarations:

1. **Comprehensive Communication Access**: `SMS` + `READ_CONTACTS` + `READ_PHONE_STATE` (communication exfiltration).
2. **Broad Physical Sensor Access**: `Location` + `CAMERA` + `RECORD_AUDIO` (ambient surveillance).
3. **Full UI Observation and Overlay Hijack**: `BIND_ACCESSIBILITY_SERVICE` + `SYSTEM_ALERT_WINDOW` (Trojan credential harvesting).
4. **Autostart Sensitive Capability**: `RECEIVE_BOOT_COMPLETED` + `SMS` / `Location` (persistent background tracking).
5. **Unverified Application Downloader**: `REQUEST_INSTALL_PACKAGES` + `INTERNET` (secondary payload dropper).

---

## 5. Contextual Alignment Analysis

Permission necessity depends on the application's declared or apparent functionality:

* **Camera Application**: `CAMERA`, `RECORD_AUDIO`, `READ_MEDIA_IMAGES` $\rightarrow$ **LOW Mismatch** (Expected).
* **Calculator Application**: `CAMERA`, `RECORD_AUDIO`, `READ_SMS`, `READ_CONTACTS` $\rightarrow$ **HIGH Mismatch** (Severe scrutiny warranted).
* **Unknown Category**: If category cannot be determined, ScamBuster records `context_status = "unknown"` and **applies zero penalty** to avoid false positives.

---

## 6. Static Bytecode API Correlation

ScamBuster correlates declared manifest permissions with actual Dalvik/DEX bytecode calls:
* **CORRELATED**: Permission declared AND matching Dalvik API signatures detected in code tables (High Confidence).
* **PERMISSION_ONLY**: Permission declared BUT no obvious API calls in primary DEX string tables (Medium Confidence).
* **API_ONLY**: Dalvik API signature detected WITHOUT corresponding permission declared in manifest (Low Confidence, potential dormant library or reflection).

---

## 7. Unified Risk Engine Integration

```text
APK Binary
   │
   ├─► Manifest & Certificate Analysis
   ├─► DEX Bytecode Heuristics
   ├─► Malware Classifier ML
   ├─► Threat Intelligence
   └─► Privacy & Permission Analyzer (Phase 08)
             │
             ▼
      Unified Risk Engine
             │
             ▼
     Composite Risk Score & Explanations
```

### Double-Counting Prevention
A permission appearing in manifest, rule findings, and bytecode is treated as correlated evidence for a single capability cluster, preventing artificial risk explosion.

---

## 8. Limitations & Boundaries

1. **Static Analysis Only**: We inspect manifest declarations and bytecode references. We do **not** claim that permissions were granted by the user or invoked at runtime.
2. **Zero Dynamic Execution**: ScamBuster never installs, executes, or launches APK binaries.
3. **No User Data Collection**: ScamBuster does not access the user's personal device, microphone, contacts, or location.
