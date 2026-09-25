# ScamBuster

## Description
**ScamBuster** is an AI-assisted cybersecurity platform designed to detect modern digital scams across multiple threat vectors:
- Phishing & malicious URLs
- SMS / text message fraud & social engineering
- Phishing emails & spoofed senders
- Suspicious phone numbers & toll-fraud patterns
- Malicious Android APKs & abnormal permission profiles

ScamBuster operates on a hybrid architecture combining rule-based cybersecurity heuristic analyzers with genuine supervised machine learning pipelines and a risk fusion engine.

---

## Architecture

The project is structured as a monorepo:

```text
User Input
    ↓
Frontend (React + TypeScript + Vite + Tailwind CSS)
    ↓
Backend API (Python FastAPI + Pydantic)
    ↓
ML Subsystem (TF-IDF NLP + Logistic Regression & URL Structural Random Forest)
    ↓
Cybersecurity Heuristic Analyzers & Risk Fusion Engine
    ↓
MongoDB Persistence Layer
```

### Monorepo Structure

```text
ScamBuster/
│
├── frontend/                   # React + TypeScript + Vite + Tailwind CSS
│   ├── src/
│   │   ├── components/         # Reusable UI components (BackendStatus, Navbar)
│   │   ├── pages/              # Placeholder pages (Home, Scan, Dashboard, History, etc.)
│   │   ├── services/           # Typed API service clients
│   │   ├── hooks/              # Custom React hooks (useBackendHealth)
│   │   ├── utils/              # UI utilities
│   │   └── App.tsx             # Application router
│   ├── package.json
│   ├── tsconfig.json
│   └── Dockerfile
│
├── backend/                    # Python FastAPI Backend
│   ├── app/
│   │   ├── main.py             # FastAPI entrypoint with CORS & lifespan
│   │   ├── api/v1/             # Versioned REST endpoints (/api/v1/health)
│   │   ├── config/             # Pydantic BaseSettings configuration
│   │   ├── database/           # Async MongoDB connection via Motor
│   │   ├── schemas/            # Pydantic request / response schemas
│   │   ├── services/           # Business logic layer
│   │   ├── security/           # CORS & security baseline
│   │   ├── risk_engine/        # Multi-vector risk fusion engine
│   │   └── ml/                 # ML inference client
│   ├── tests/                  # Pytest test suite
│   ├── requirements.txt
│   └── Dockerfile
│
├── ml/                         # Dedicated Machine Learning Subsystem
│   ├── datasets/               # Public datasets (raw & processed)
│   ├── preprocessing/          # Text cleaner & URL structural parser
│   ├── features/               # TF-IDF vectorizer & 17 URL feature extractors
│   ├── training/               # Supervised training pipelines
│   ├── evaluation/             # Metrics calculation & test evaluation
│   ├── inference/              # Stateless prediction modules
│   ├── models/                 # Saved model artifacts (.joblib)
│   └── api/                    # Independent FastAPI ML inference service
│
├── docs/                       # Architecture & design documentation
├── tests/                      # Integration test suites
├── docker-compose.yml          # Container orchestration (Frontend, Backend, MongoDB)
├── .env.example                # Environment template
├── .gitignore
├── README.md
└── SCAMBUSTER_MASTER_SPEC.md   # Single source of truth specification
```

---

## Requirements

- **Node.js** >= 18.x
- **Python** >= 3.10 (Tested on Python 3.14)
- **MongoDB** >= 6.0 (or Docker)
- **Docker & Docker Compose** (Optional for containerized execution)

---

## Local Development

### 1. Environment Configuration
Copy the template environment file:
```bash
cp .env.example .env
```

### 2. Run MongoDB
Start a local MongoDB instance or run via Docker:
```bash
docker run -d -p 27017:27017 --name scambuster-mongo mongo:7.0
```

### 3. Run Backend (FastAPI)
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
- API Base URL: `http://localhost:8000`
- Base Health: `http://localhost:8000/api/v1/health`
- Swagger Docs: `http://localhost:8000/docs`

### 4. Run Frontend (React + Vite + Tailwind)
```bash
cd frontend
npm install
npm run dev
```
- Frontend UI: `http://localhost:5173`

---

## Docker Development

To run the entire platform (Frontend, Backend, MongoDB) using Docker Compose:

```bash
docker compose up --build
```

To stop all services:
```bash
docker compose down
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
| `VITE_API_URL` | Backend API URL for frontend client | `http://localhost:8000` |
