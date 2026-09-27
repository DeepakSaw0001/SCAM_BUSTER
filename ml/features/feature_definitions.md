# ScamBuster URL Feature Definitions

This document details the complete 23-dimensional feature space engineered for the ScamBuster URL machine-learning classification pipeline.
These features are extracted deterministically by `backend/app/services/url_feature_extractor.py` and consumed identically across training and inference.

---

## 1. Length Metrics

### `url_length`
- **Type:** Integer
- **Meaning:** Total character count of the complete URL string.
- **Why it is useful:** Phishing URLs frequently exhibit abnormal lengths to embed redirect chains, obfuscated tracking IDs, or push deceptive path segments out of visible mobile address bars.
- **Potential limitations:** Some legitimate enterprise URLs (e.g. AWS S3 presigned URLs, SSO redirects) are also very long.

### `hostname_length`
- **Type:** Integer
- **Meaning:** Total character count of the fully qualified domain name / hostname.
- **Why it is useful:** Attackers frequently create verbose hostnames containing multiple concatenated brand names to mislead users.
- **Potential limitations:** Certain legitimate multi-tenant services have naturally long subdomains.

### `path_length`
- **Type:** Integer
- **Meaning:** Character length of the hierarchical path component following the authority.
- **Why it is useful:** Credential harvesting portals often employ deeply nested directories mimicking legitimate internal portal paths.
- **Potential limitations:** Content management systems (CMS) and blogs routinely use descriptive, long path slugs.

### `query_length`
- **Type:** Integer
- **Meaning:** Length of the raw query parameter string.
- **Why it is useful:** Automated phishing campaigns embed campaign IDs, victim email addresses, or base64 payloads inside query parameters.
- **Potential limitations:** Legitimate search engines and analytics tracking links also possess long query strings.

### `fragment_length`
- **Type:** Integer
- **Meaning:** Length of the URL hash fragment.
- **Why it is useful:** Client-side single-page phishing apps sometimes hide payloads or credential states behind hash fragments to avoid server-side logging.
- **Potential limitations:** Standard single-page applications (SPAs) utilize fragments for client-side routing.

---

## 2. Character Counts

### `number_of_dots`
- **Type:** Integer
- **Meaning:** Count of period (`.`) characters in the URL.
- **Why it is useful:** Elevated dot counts correlate strongly with deep subdomain nesting and multi-level domain emulation.
- **Potential limitations:** File downloads and file extensions (e.g., `.tar.gz`) naturally increase dot counts.

### `number_of_hyphens`
- **Type:** Integer
- **Meaning:** Count of dash (`-`) characters in the URL.
- **Why it is useful:** Phishing domains frequently use hyphenated brand names (e.g. `paypal-security-update.com`).
- **Potential limitations:** Many legitimate modern brands and e-commerce websites use hyphens for SEO slugs.

### `number_of_digits`
- **Type:** Integer
- **Meaning:** Total numeric digits (0–9) across the URL.
- **Why it is useful:** Raw IP hostnames, dynamic session hashes, and auto-generated phishing domains feature heavy digit densities.
- **Potential limitations:** Legitimate order IDs and database record IDs in queries contain numeric sequences.

### `number_of_special_characters`
- **Type:** Integer
- **Meaning:** Count of punctuation and symbol characters (`!@#$%^&*()_+={}[]|\:";<>,?~``).
- **Why it is useful:** Heavy symbol densities frequently reflect encoded payloads, credential spoofing, and parameter stuffing.
- **Potential limitations:** Complex REST query filters legitimately employ symbols.

### `number_of_slashes`
- **Type:** Integer
- **Meaning:** Count of forward slash (`/`) characters in the URL.
- **Why it is useful:** Slashes indicate directory depth and path traversal attempts.
- **Potential limitations:** Deep directory structures on large documentation and news websites increase slash counts.

### `number_of_question_marks`
- **Type:** Integer
- **Meaning:** Count of `?` characters.
- **Why it is useful:** Standard URLs contain at most one `?`. Multiple question marks indicate parameter injection or malformed obfuscation.
- **Potential limitations:** Malformed user input can introduce extra question marks.

### `number_of_equals`
- **Type:** Integer
- **Meaning:** Count of `=` characters.
- **Why it is useful:** Measures the quantity of key-value pairs in query parameters.
- **Potential limitations:** Complex API queries legitimately use many key-value pairs.

---

## 3. Structural Attributes

### `subdomain_count`
- **Type:** Integer
- **Meaning:** Number of subdomain labels preceding the registered domain.
- **Why it is useful:** Attackers frequently prepend legitimate brand names as subdomains (e.g., `login.chase.com.evil-domain.com`).
- **Potential limitations:** Cloud environments and CDNs legitimately use 2–3 levels of subdomains.

### `path_depth`
- **Type:** Integer
- **Meaning:** Number of directory levels in the path (e.g., `/a/b/c/` has depth 3).
- **Why it is useful:** Phishing kits are often deposited in deeply nested subfolders on compromised web servers.
- **Potential limitations:** Content repositories naturally have deep hierarchies.

### `query_parameter_count`
- **Type:** Integer
- **Meaning:** Distinct parsed query arguments.
- **Why it is useful:** Differentiates static destination pages from parameter-stuffed redirectors.
- **Potential limitations:** Tracking links (UTM parameters) frequently populate multiple query parameters.

### `has_ip_hostname`
- **Type:** Boolean (0.0 or 1.0)
- **Meaning:** Whether the URL host is represented directly by a numeric IPv4 address.
- **Why it is useful:** Direct IP addresses bypass domain reputation systems and DNS controls; strong phishing and C2 indicator.
- **Potential limitations:** Internal network links (e.g., router configuration portals) use IP addresses legitimately.

### `has_port`
- **Type:** Boolean (0.0 or 1.0)
- **Meaning:** Whether a non-standard port is specified (other than 80 for HTTP or 443 for HTTPS).
- **Why it is useful:** Malware drop sites and unauthorized phishing staging servers frequently operate on irregular high ports.
- **Potential limitations:** Development and local testing environments use custom ports (e.g., 8000, 8080).

### `uses_https`
- **Type:** Boolean (0.0 or 1.0)
- **Meaning:** Whether the protocol scheme is HTTPS.
- **Why it is useful:** Captures transport security baseline.
- **Potential limitations:** Modern phishing sites frequently obtain free Let's Encrypt SSL certificates, so HTTPS alone does NOT prove a site is safe.

---

## 4. Encoding & Obfuscation Signals

### `has_at_symbol`
- **Type:** Boolean (0.0 or 1.0)
- **Meaning:** Whether the `@` character appears in the URL authority section.
- **Why it is useful:** Browsers interpret text before `@` as userinfo and navigate exclusively to the host following `@` (classic phishing deception).
- **Potential limitations:** Rare legitimate HTTP basic authentication links utilize `@`.

### `has_double_slash_redirect`
- **Type:** Boolean (0.0 or 1.0)
- **Meaning:** Whether `//` occurs inside the URL path component after the scheme.
- **Why it is useful:** Indicates open redirect exploitation where an attacker attempts to redirect a user away from a trusted domain.
- **Potential limitations:** Malformed routing rules on buggy web servers may inadvertently produce double slashes.

---

## 5. Lexical & Statistical Indicators

### `suspicious_keyword_count`
- **Type:** Integer
- **Meaning:** Number of high-risk credential and authentication keywords matched in the URL string (`login`, `verify`, `account`, `password`, `update`, `bank`, `wallet`, `confirm`, `signin`, etc.).
- **Why it is useful:** Phishing portals overwhelmingly target credentials, identity verification, and financial access.
- **Potential limitations:** Legitimate corporate login pages naturally contain keywords like `login` and `account`. Must be evaluated in combination with structural features.

### `digit_ratio`
- **Type:** Float (0.0 to 1.0)
- **Meaning:** Ratio of numeric digits to the total URL character length.
- **Why it is useful:** Domain generation algorithms (DGA) and IP-based URLs exhibit elevated digit ratios compared to natural language URLs.
- **Potential limitations:** Date-based or timestamped URLs will have higher digit ratios.

### `entropy`
- **Type:** Float
- **Meaning:** Shannon entropy measuring character randomness across the URL string.
- **Why it is useful:** DGA domains, encrypted parameters, and base64 obfuscated tokens exhibit high entropy ($\ge 4.2$).
- **Potential limitations:** Natural language text can occasionally yield moderate entropy depending on vocabulary diversity.
