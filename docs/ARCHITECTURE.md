# ScamBuster — Architecture Document

## Overview

ScamBuster follows a three-tier architecture: React frontend, Node.js/Express API backend, and MongoDB persistence layer, with a modular analysis engine designed for progressive enhancement.

---

## Architecture Diagram

```
┌──────────────────────────────────────────────────────┐
│                    CLIENT (React)                     │
│                                                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │   Pages  │  │Components│  │  Services (API)  │   │
│  │Dashboard │  │ Navbar   │  │  api.js           │   │
│  │ Analyze  │  │RiskBadge │  │  (fetch wrapper)  │   │
│  │ History  │  │AnalysisR │  └────────┬─────────┘   │
│  │  About   │  └──────────┘           │              │
│  └──────────┘                         │              │
└───────────────────────────────────────┼──────────────┘
                                        │ HTTP (JSON)
                                        │ Vite dev proxy: /api → :5000
┌───────────────────────────────────────┼──────────────┐
│                    SERVER (Express)    │              │
│                                       ▼              │
│  ┌─────────────────────────────────────────────┐     │
│  │              Middleware Stack                │     │
│  │  Helmet → CORS → Rate Limit → Body Parse    │     │
│  └─────────────────────┬───────────────────────┘     │
│                        ▼                             │
│  ┌──────────────────────────────────────────┐        │
│  │              Routes (/api)               │        │
│  │  /health  │  /analysis/submit            │        │
│  │           │  /analysis/history            │        │
│  │           │  /analysis/:id               │        │
│  └───────────┴──────────┬───────────────────┘        │
│                         ▼                            │
│  ┌──────────────────────────────────────────┐        │
│  │           Controllers                    │        │
│  │  analysisController.js                   │        │
│  └──────────────────┬───────────────────────┘        │
│                     ▼                                │
│  ┌──────────────────────────────────────────┐        │
│  │         Analysis Engine Service          │        │
│  │  ┌────────────────────────────────────┐  │        │
│  │  │         analysisEngine.js          │  │        │
│  │  │   Routes input → correct analyzer  │  │        │
│  │  └───────────┬────────────────────────┘  │        │
│  │              ▼                           │        │
│  │  ┌──────────────────────────────────┐    │        │
│  │  │         Analyzers                │    │        │
│  │  │  ┌────────────┐ ┌────────────┐   │    │        │
│  │  │  │urlAnalyzer │ │msgAnalyzer │   │    │        │
│  │  │  └────────────┘ └────────────┘   │    │        │
│  │  │  ┌────────────┐ ┌────────────┐   │    │        │
│  │  │  │emailAnalyz │ │phoneAnalyz │   │    │        │
│  │  │  └────────────┘ └────────────┘   │    │        │
│  │  └──────────────────────────────────┘    │        │
│  └──────────────────────────────────────────┘        │
│                     ▼                                │
│  ┌──────────────────────────────────────────┐        │
│  │           Models (Mongoose)              │        │
│  │  Analysis.js                             │        │
│  └──────────────────┬───────────────────────┘        │
└─────────────────────┼────────────────────────────────┘
                      ▼
┌──────────────────────────────────────────────────────┐
│                 DATABASE (MongoDB)                    │
│  Collection: analyses                                │
│  (Optional — system works without DB)                │
└──────────────────────────────────────────────────────┘
```

---

## Frontend Architecture

- **Framework**: React 18 with Vite
- **Routing**: React Router v6
- **State**: Local component state (no global store needed yet)
- **Theming**: CSS custom properties with `data-theme` attribute switching
- **API**: Centralized fetch wrapper in `services/api.js`
- **Styling**: Vanilla CSS design system with semantic class names

### Key Design Decisions
- No CSS framework dependency — full control over styling
- Vite proxy eliminates CORS issues during development
- Theme persisted in localStorage

---

## Backend Architecture

- **Framework**: Express 4
- **Security**: Helmet (HTTP headers), CORS (origin control), express-rate-limit
- **Validation**: Lightweight custom middleware (no Joi/Zod dependency)
- **Error Handling**: Centralized `AppError` class + global error middleware
- **Database**: Mongoose ODM with graceful offline handling

### Key Design Decisions
- Server continues running without MongoDB — analysis works, just doesn't persist
- Centralized config reads env vars once
- Rate limiting prevents abuse (100 requests / 15 min)

---

## Analysis Engine Architecture

The engine is designed for progressive enhancement:

```
Current:   Input → Heuristic Analyzer → Score + Reasons
Future:    Input → [Heuristic + ML Model + External APIs] → Aggregated Score
```

### Analyzer Interface

Each analyzer exports:
```javascript
module.exports = {
  analyze: async (input) => ({
    riskLevel,      // CRITICAL | HIGH | MEDIUM | LOW | SAFE
    riskScore,      // 0-100
    reasons,        // string[]
    indicators,     // { name, description, severity }[]
    recommendations // string[]
  })
};
```

### Current Analyzers
1. **URL Analyzer** — Domain structure, TLDs, brand impersonation, phishing keywords
2. **Message Analyzer** — Social engineering, urgency, financial lures, credential requests
3. **Email Analyzer** — Inherits message analysis + email-specific header checks
4. **Phone Analyzer** — Premium-rate detection, high-risk prefixes, format validation

---

## Future: AI/ML Layer

Planned integration points:

1. **NLP Text Classifier** — Trained model for scam/ham classification of messages/emails
2. **URL Reputation** — VirusTotal, Google Safe Browsing API integration
3. **Domain Intelligence** — WHOIS age, registration data analysis
4. **File Analysis** — Static APK analysis, malware signature matching
5. **Ensemble Scoring** — Combine heuristic + ML + external API results

The analyzer interface is designed so ML models can be added as new analyzers or as enhancements to existing ones without changing the controller/route layer.

---

## Communication Flow

1. User submits content via React frontend
2. Frontend sends `POST /api/analysis/submit` with `{ inputType, inputValue }`
3. Backend validates input
4. Analysis engine routes to correct analyzer
5. Analyzer returns structured result with score + reasons
6. Result is persisted to MongoDB (if available)
7. JSON response returned to frontend
8. Frontend renders result with risk visualization
