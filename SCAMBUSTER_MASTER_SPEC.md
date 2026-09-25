# SCAMBUSTER — MASTER SPECIFICATION

## Overview
ScamBuster is an AI-assisted cybersecurity platform for detecting modern scams across URLs, SMS, emails, phone numbers, and APKs.

The platform combines:
1. Heuristic Cybersecurity Detection Engines
2. Machine Learning Classifiers (Statistical Signal Analysis)
3. Risk Fusion Engine for correlated, explainable threat scoring

---

## Phase 01: Project Foundation

### Stack
- **Frontend:** React, TypeScript, Vite, Tailwind CSS
- **Backend:** Python, FastAPI, Pydantic, Motor/MongoDB
- **ML Subsystem:** Python, scikit-learn, joblib
- **Database:** MongoDB
- **Infrastructure:** Docker, Docker Compose, Git
- **Testing:** Pytest (Backend), Vitest/Testing Library (Frontend)

### Directory Layout
```text
ScamBuster/
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── hooks/
│   │   ├── utils/
│   │   └── App.tsx
│   ├── package.json
│   └── Dockerfile
│
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── config/
│   │   ├── database/
│   │   ├── schemas/
│   │   ├── services/
│   │   ├── security/
│   │   ├── risk_engine/
│   │   └── ml/
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml/
│   ├── datasets/
│   ├── preprocessing/
│   ├── features/
│   ├── training/
│   ├── evaluation/
│   ├── inference/
│   └── models/
│
├── docs/
├── tests/
├── docker-compose.yml
├── .env.example
├── .gitignore
├── README.md
└── SCAMBUSTER_MASTER_SPEC.md
```

### Base API
- Base path: `/api/v1`
- Health check: `GET /api/v1/health`
  ```json
  {
    "status": "ok",
    "service": "scambuster-api"
  }
  ```
