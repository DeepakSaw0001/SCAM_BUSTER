# ScamBuster — Phase 10: Advanced Email, SMS & Social Engineering Intelligence

## 1. Executive Summary

Phase 10 upgrades ScamBuster's textual and communication security vectors into an enterprise-grade **Social Engineering Intelligence & Deception Detection Subsystem**. Attackers rarely present malware in isolation; rather, they combine psychological manipulation (urgency, intimidation, fake windfalls), visual deception (brand lookalikes, hidden anchor link mismatches), and structural evasion (leetspeak, zero-width spaces, character spreading, defanged links) to coerce victims into surrendering credentials, one-time passwords (OTPs), or financial assets.

Phase 10 introduces:
- **Centralized 21-Category Social Engineering Taxonomy**: Standardized semantic classification covering modern cybercrime modalities (Tech Support, BEC, Wangiri, Delivery Phishing, Tax Extortion, etc.).
- **Lexical Normalization & Anti-Obfuscation**: Automated de-spacing, homoglyph flattening, zero-width space elimination, defanged URL restoration, and leetspeak substitution.
- **Multilingual Support**: Support for English, Hindi (Devanagari), Marathi, and Hinglish transliterated scams.
- **Safe HTML & Structural Anchor Verification**: Zero JavaScript execution, zero remote rendering HTML extractor that exposes deceptive anchor text where displayed domains diverge from underlying destinations.
- **Brand Intelligence & Lookalike Domain Engine**: In-memory catalog of high-target banking, e-commerce, cloud, and government entities, analyzing typosquatting, combosquatting, and display name spoofing.
- **Attachment Risk Analyzer**: Identification of double extensions (`.pdf.exe`), raw executable scripts (`.ps1`, `.bat`, `.vbs`), macro-enabled office docs, mobile packages (`.apk`), and archive inspection.
- **Zero-Retention PII & Secret Redaction Engine**: Automatic sanitization of OTPs, credit cards (Luhn-checked), API keys, passwords, emails, and phone numbers in runtime logs and telemetry.
- **Multi-Signal Corroboration Engine**: Fusion logic elevating threat floors and analytical confidence when multiple distinct manipulation vectors corroborate.

---

## 2. 21-Category Social Engineering Taxonomy

| Category | Identifier | Severity Tier | Threat Description |
| :--- | :--- | :--- | :--- |
| **Phishing** | `PHISHING` | HIGH | Traditional credential and identity theft lures masquerading as known portals. |
| **Smishing** | `SMISHING` | HIGH | SMS/RCS-based deception pushing victims toward malicious links or numbers. |
| **Vishing** | `VISHING` | HIGH | Voice-based lures and callback requests coercing direct telephony engagement. |
| **Urgency** | `URGENCY` | MEDIUM | Artificial deadlines, countdown pressure, and threats of imminent disruption. |
| **Fear / Coercion** | `FEAR` | HIGH | Intimidation involving law enforcement, lawsuits, tax evasion, or arrest warrants. |
| **Reward / Win** | `REWARD` | MEDIUM | Unsolicited lottery, prize, windfall, or crypto-doubling financial bait. |
| **Credential Theft** | `CREDENTIAL_THEFT` | CRITICAL | Direct or indirect harvesting of passwords, PINs, security questions, or private keys. |
| **OTP Scam** | `OTP_SCAM` | CRITICAL | Solicitation of one-time authentication codes under the guise of security verification. |
| **Brand Impersonation**| `IMPERSONATION` | HIGH | Display name, domain, or trademark spoofing targeting trusted organizations. |
| **Lookalike Domain** | `LOOKALIKE_DOMAIN` | HIGH | Typosquatted, combosquatted, or hyphenated domains designed to mislead. |
| **Malicious Link** | `MALICIOUS_LINK` | HIGH | Embedded hyperlinks pointing to threat infrastructure, phishing kits, or droppers. |
| **Malicious File** | `MALICIOUS_ATTACHMENT` | CRITICAL | Executable attachments, macro documents, double extensions, or APK droppers. |
| **Support Scam** | `TECH_SUPPORT` | HIGH | Fabricated malware alerts prompting calls to toll-free lines or RAT downloads. |
| **Investment Scam** | `INVESTMENT_FRAUD` | HIGH | Fraudulent guaranteed-return schemes, high-yield crypto platforms, and fake brokers. |
| **Job Scam** | `JOB_FRAUD` | MEDIUM | Unsolicited task-based employment offers requiring upfront deposits or registration fees. |
| **Romance Scam** | `ROMANCE_SCAM` | MEDIUM | Relationship grooming culminating in urgent cross-border financial assistance requests. |
| **Govt Impersonation**| `GOVERNMENT_IMPERSONATION` | HIGH | Spoofing tax authorities, judicial bodies, police, or national identity bureaus. |
| **Delivery Scam** | `DELIVERY_SCAM` | MEDIUM | Smishing/phishing alerts regarding delayed packages and redelivery fees. |
| **Refund Scam** | `REFUND_SCAM` | HIGH | Overpayment reversals requiring victims to purchase gift cards or execute remote access. |
| **Advance-Fee Fraud**| `ADVANCE_FEE` | MEDIUM | 419-style inheritance, lottery clearance, or customs duties required to release funds. |
| **Account Takeover** | `ACCOUNT_TAKEOVER` | CRITICAL | Interception of account credentials to lock out legitimate account holders. |

---

## 3. Lexical Normalization & Anti-Obfuscation Pipeline

Before text reaches NLP classifiers or heuristic regexes, `normalize_message_input()` applies a five-tier deterministic cleaning pipeline:

1. **Defanged URL Restoration**:
   - `hxxps://victim[.]com/login` $\to$ `https://victim.com/login`
   - `example(dot)com` $\to$ `example.com`
2. **Homoglyph & Unicode Normalization**:
   - NFKD decomposition converting Cyrillic / Greek confusable glyphs (e.g., Cyrillic 'а', 'р', 'о' $\to$ Latin 'a', 'p', 'o').
   - Stripping zero-width joiners (`\u200B`, `\u200C`, `\u200D`, `\uFEFF`).
3. **De-Spacing of Evasive Keywords**:
   - Recombines split keywords such as `p a s s w o r d` $\to$ `password`, `v e r i f y` $\to$ `verify`, `u r g e n t` $\to$ `urgent`.
4. **Leetspeak De-obfuscation**:
   - Resolves symbol substitutions such as `p@ssw0rd` $\to$ `password`, `b4nk` $\to$ `bank`.
5. **Multilingual Detection**:
   - Identifies English, Hindi (Devanagari script), Marathi, and Latin-script Hinglish scams (e.g., "aapka account band ho gaya hai").

---

## 4. Safe HTML Extraction & Anchor Mismatch Detection

Phishing emails frequently employ visual camouflage where the visible anchor text displays a legitimate entity (`https://www.chase.com/login`), while the underlying `href` destination routes to a credential harvester (`http://chase-security-verify.ru/login`).

- **Zero Remote Rendering**: Parses raw markup with Python `BeautifulSoup` (html.parser). No external resources, remote fonts, stylesheets, or JavaScript engines are executed.
- **Structural Anomaly Extraction**:
  - Hidden zero-pixel `<iframe>` tags and off-screen hidden input elements.
  - Form action destinations pointing across third-party domains.
- **Anchor Mismatch Evaluator**:
  - Normalizes both visible text and actual link destination into their Fully Qualified Domain Names (FQDN).
  - Triggers `RULE_SE_ANCHOR_MISMATCH` with CRITICAL severity when the displayed FQDN represents a trusted financial or corporate entity while the destination domain resolves elsewhere.

---

## 5. Sender Consistency & Header Verification

Email spoofing remains a cornerstone of spear-phishing and Business Email Compromise (BEC).

`analyze_sender_consistency()` parses raw MIME headers to detect:
1. **Reply-To / From Domain Divergence**: Attacker sends from a compromised or lookalike sender domain but diverts victim responses to an untrusted webmail address.
2. **Display Name Impersonation**: Attacker sets the friendly display name to `"Chase Bank Security"` while the underlying address is `attacker@external-drop.net`.
3. **Authentication Verification**: Evaluates SPF, DKIM, and DMARC results from the `Authentication-Results` header. Missing or failing authentication paired with brand keywords triggers elevated risk flags.

---

## 6. Privacy & PII Redaction Engine

ScamBuster guarantees enterprise privacy: raw sensitive credentials and personal information are redacted prior to log output or long-term persistence:
- **One-Time Passwords (OTPs)**: 4 to 8-digit numeric tokens in verification contexts are masked to `[REDACTED_OTP]`.
- **Payment Cards**: 13 to 19-digit numbers are validated against the Luhn algorithm and masked to `4111-****-****-1111`.
- **Email Addresses & Phone Numbers**: Masked to `u***t@domain.com` and `+14***71`.
- **API Keys & Secrets**: High-entropy hexadecimal and Base64 secrets are replaced with `[REDACTED_SECRET]`.

---

## 7. Unified Corroboration & Risk Engine

When independent threat signals converge on a communication, ScamBuster elevates both the baseline score and analytical confidence:

$$\text{Vectors Active} \in \{\text{credential\_harvesting, urgency, intimidation, financial\_lure, brand\_impersonation, malicious\_url, suspicious\_phone, ml\_threat}\}$$

- **3+ Vectors Active**: Composite risk floor set to $\ge 82$ (CRITICAL), analytical confidence elevated to $0.95$.
- **2 Vectors Active**: Composite risk floor set to $\ge 72$ (HIGH), analytical confidence set to $0.92$.
- **Clean Baseline**: Absence of heuristic triggers, clean lexical metrics, and benign ML prediction guarantees composite risk $\le 5$ (VERY LOW).

---

## 8. Test Verification

The entire ScamBuster test suite verifies all Phase 01–10 features across **245 unit, integration, and security tests**:
- Social Engineering pipeline tests: **33 passed** (`backend/tests/test_social_engineering_pipeline.py`)
- Complete workspace tests: **245 passed** (`backend/tests/`)
- Frontend production bundle: **0 errors** (`dist/` verified via Vite and TypeScript compiler)
