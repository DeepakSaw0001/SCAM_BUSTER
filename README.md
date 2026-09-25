# ScamBuster

## Description
**ScamBuster** is an AI-assisted cybersecurity platform designed to detect modern digital scams across multiple threat vectors:
- Phishing & malicious URLs
- SMS / text message fraud & social engineering
- Phishing emails & spoofed senders
- Suspicious phone numbers & toll-fraud patterns
- Malicious Android APKs & abnormal permission profiles

ScamBuster operates on a hybrid architecture combining rule-based cybersecurity heuristic analyzers with supervised machine learning pipelines and an explainable risk engine.

---

## Phase 02: URL Scanner & Risk Engine Foundation

Phase 02 establishes ScamBuster's first complete vertical detection slice:
```text
User Input → Frontend URL Scanner → FastAPI → URL Validation → URL Normalization → URL Feature Extraction → Rule-Based Detection Engine → Risk Engine → Explainable Result → Frontend Display
```

> **Note on Architecture:** Hybrid architecture prepared; current URL detector uses rule-based analysis (`model_version: "rules-v1"`). Machine learning classification models are planned separately and will consume the identical structured feature extraction pipeline.

### API Endpoint: `POST /api/v1/scan/url`

**Request:**
```json
{
  "url": "http://192.168.1.1/paypal/login.php?update=true"
}
```

**Response:**
```json
{
  "scan_id": "6142c400-08e4-4b28-987e-aed716e4c1f6",
  "input_type": "url",
  "status": "completed",
  "target": "http://192.168.1.1/paypal/login.php?update=true",
  "risk_score": 80,
  "risk_level": "CRITICAL",
  "category": [
    "potential_phishing",
    "credential_harvesting",
    "suspicious_infrastructure",
    "unencrypted_transport"
  ],
  "confidence": 0.82,
  "summary": "Multiple suspicious URL indicators were detected (IP-based Hostname, Suspicious Keyword Pattern, Unencrypted HTTP Transport). The structure indicates elevated risk consistent with phishing or deceptive redirection.",
  "indicators": [
    {
      "name": "IP-based Hostname",
      "severity": "HIGH",
      "description": "The URL uses a raw IP address instead of a registered domain name, common in phishing and command-and-control infrastructure.",
      "evidence": "Hostname: 192.168.1.1",
      "rule_id": "RULE_IP_HOSTNAME"
    },
    {
      "name": "Suspicious Keyword Pattern",
      "severity": "HIGH",
      "description": "The URL contains a cluster of credential and urgency-related keywords frequently leveraged in credential harvesting portals.",
      "evidence": "Matched keywords: login, update",
      "rule_id": "RULE_KEYWORD_PATTERN"
    },
    {
      "name": "Unencrypted HTTP Transport",
      "severity": "LOW",
      "description": "The URL uses unencrypted HTTP instead of HTTPS. While not inherently malicious, it allows traffic eavesdropping and credential interception.",
      "evidence": "Protocol scheme: http://",
      "rule_id": "RULE_UNENCRYPTED_HTTP"
    }
  ],
  "recommendation": "Avoid entering passwords, OTPs, or payment information. Do not download or execute any files from this address.",
  "model_version": "rules-v1",
  "created_at": "2026-09-25T16:35:09.633797Z"
}
```

### Security & Limitations (Phase 02)
- **Zero SSRF (Static Lexical Only):** To prevent Server-Side Request Forgery (SSRF) and avoid interacting with untrusted infrastructure, the scanner performs purely static lexical and structural analysis. It does **NOT** issue outbound HTTP requests (`requests.get`) to the analyzed URL.
- **Strict Scheme Validation:** Only `http://` and `https://` schemes are accepted. Pseudo-schemes (`javascript:`, `data:`, `file:`, `ftp:`) are strictly rejected with HTTP 422.
- **Provisional Scoring Scale:** Risk scores (0–100) are provisional heuristic weights designed to combine multiple independent signals without false confidence. They will be statistically calibrated in future ML validation phases.

---

## Monorepo Layout

```text
ScamBuster/
│
├── frontend/                   # React 18 + TypeScript + Vite + Tailwind CSS
│   ├── src/
│   │   ├── components/         # Reusable UI components (ScanResultCard, Navbar)
│   │   ├── pages/              # Scanner Hub, ScanUrl, History, Dashboard
│   │   ├── services/           # Typed API service client
│   │   └── App.tsx             # Application router
│   ├── package.json
│   └── Dockerfile
│
├── backend/                    # Python FastAPI Backend
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint with CORS & lifespan
│   │   ├── api/v1/             # Versioned REST endpoints (/api/v1/scan/url)
│   │   ├── services/           # Dedicated validator, normalizer, feature extractor, rules
│   │   │   ├── url_validator.py
│   │   │   ├── url_normalizer.py
│   │   │   ├── url_feature_extractor.py
│   │   │   └── url_rule_detector.py
│   │   ├── risk_engine/        # Modular risk scoring, categories, explanations
│   │   │   ├── scorer.py
│   │   │   ├── categories.py
│   │   │   └── explanations.py
│   │   ├── database/           # Async MongoDB connection via Motor & scan repository
│   │   └── schemas/            # Pydantic request / response schemas
│   ├── tests/                  # Pytest test suite (56 tests)
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml/                         # Machine Learning Subsystem
│   ├── datasets/               # Public datasets
│   ├── features/               # Feature extraction vectors
│   ├── models/                 # Model artifacts (.joblib)
│   └── inference/              # Inference modules
│
├── docs/                       # Architecture & design documentation
├── tests/                      # Integration test suites
├── docker-compose.yml          # Container orchestration (Frontend, Backend, MongoDB)
├── .env.example                # Environment template
└── SCAMBUSTER_MASTER_SPEC.md   # Single source of truth specification
```

---

## Testing

Run the automated backend test suite:
```bash
cd backend
pytest -v
```

Or run integration tests from the repository root:
```bash
pytest tests/test_api_v1.py -v
```

---

## Environment Variables

| Variable | Description | Default |
|---|---|---|
| `APP_ENV` | Application environment (`development`, `production`) | `development` |
| `DATABASE_URL` | MongoDB connection URI | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Target MongoDB database | `scambuster` |
| `JWT_SECRET` | Secret key for JWT signing | Minimum 32 characters |
| `CORS_ORIGINS` | JSON list of allowed origins | `["http://localhost:5173"]` |
