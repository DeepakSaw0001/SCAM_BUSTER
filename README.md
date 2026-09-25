# 🛡️ ScamBuster

**AI-powered cybersecurity web application for detecting and explaining potential scams, phishing, malicious URLs, suspicious messages, and fraudulent phone numbers.**

ScamBuster is a final-year engineering project combining Cybersecurity and AI/ML to create a practical, explainable scam detection tool.

---

## 🚀 Technologies

| Layer | Technology |
|-------|-----------|
| Frontend | React 18, Vite 5, React Router 6 |
| Backend | Node.js, Express 4 |
| Database | MongoDB (via Mongoose 8) |
| Security | Helmet, CORS, Rate Limiting |
| Detection | Heuristic rule-based engine (v1) |

---

## 📁 Project Structure

```
SCAM_BUSTER/
│
├── client/                    # React frontend (Vite)
│   ├── public/                # Static assets
│   ├── src/
│   │   ├── components/        # Reusable UI components
│   │   │   ├── Navbar.jsx
│   │   │   ├── RiskBadge.jsx
│   │   │   └── AnalysisResult.jsx
│   │   ├── pages/             # Route pages
│   │   │   ├── Dashboard.jsx
│   │   │   ├── Analyze.jsx
│   │   │   ├── History.jsx
│   │   │   └── About.jsx
│   │   ├── services/          # API abstraction layer
│   │   │   └── api.js
│   │   ├── hooks/             # Custom React hooks
│   │   │   └── useTheme.jsx
│   │   ├── App.jsx
│   │   ├── main.jsx
│   │   └── index.css          # Design system & global styles
│   ├── index.html
│   ├── vite.config.js
│   └── package.json
│
├── server/                    # Express backend
│   ├── src/
│   │   ├── config/
│   │   │   ├── index.js       # Environment configuration
│   │   │   └── database.js    # MongoDB connection
│   │   ├── controllers/
│   │   │   └── analysisController.js
│   │   ├── middleware/
│   │   │   ├── errorHandler.js
│   │   │   └── validate.js
│   │   ├── models/
│   │   │   └── Analysis.js    # Mongoose schema
│   │   ├── routes/
│   │   │   ├── index.js
│   │   │   ├── health.js
│   │   │   └── analysis.js
│   │   ├── services/
│   │   │   ├── analysisEngine.js    # Central analysis router
│   │   │   └── analyzers/
│   │   │       ├── urlAnalyzer.js
│   │   │       ├── messageAnalyzer.js
│   │   │       ├── emailAnalyzer.js
│   │   │       └── phoneAnalyzer.js
│   │   └── app.js             # Express entry point
│   └── package.json
│
├── docs/
│   └── ARCHITECTURE.md
│
├── .env                       # Local environment (not committed)
├── .env.example               # Environment template
├── .gitignore
└── README.md
```

---

## 🔧 Local Setup

### Prerequisites

- Node.js 18+
- npm 9+
- MongoDB (optional — app runs without it, history just won't persist)

### 1. Clone & Install

```bash
# Install backend dependencies
cd server
npm install

# Install frontend dependencies
cd ../client
npm install
```

### 2. Environment Variables

Copy `.env.example` to `.env` in the project root:

```bash
cp .env.example .env
```

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `5000` | Backend server port |
| `NODE_ENV` | `development` | Environment mode |
| `MONGODB_URI` | `mongodb://localhost:27017/scambuster` | MongoDB connection string |
| `CLIENT_URL` | `http://localhost:5173` | Frontend URL (for CORS) |

### 3. Start the Backend

```bash
cd server
npm run dev
```

The API will be available at `http://localhost:5000`. Health check: `GET http://localhost:5000/api/health`

### 4. Start the Frontend

```bash
cd client
npm run dev
```

The app will be available at `http://localhost:5173`.

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/analysis/submit` | Submit content for analysis |
| `GET` | `/api/analysis/history` | Get analysis history (requires MongoDB) |
| `GET` | `/api/analysis/:id` | Get specific analysis by ID |

### Submit Analysis Example

```bash
curl -X POST http://localhost:5000/api/analysis/submit \
  -H "Content-Type: application/json" \
  -d '{"inputType": "url", "inputValue": "http://secure-bank-login.xyz/verify-account"}'
```

---

## ✅ Currently Implemented

- [x] Express backend with security middleware (Helmet, CORS, rate limiting)
- [x] Health check endpoint
- [x] Heuristic analysis engine with 4 analyzers (URL, Email, Message, Phone)
- [x] 30+ detection rules across all analyzers
- [x] MongoDB persistence with graceful offline handling
- [x] React frontend with Vite
- [x] Responsive design with light/dark theme
- [x] Dashboard with system status
- [x] Analysis submission interface
- [x] Analysis result display with risk score, reasons, indicators, recommendations
- [x] Analysis history page
- [x] About page with project documentation
- [x] Centralized error handling
- [x] API service abstraction

## 🔮 Planned Features

- [ ] ML-based text classification model (NLP scam detection)
- [ ] VirusTotal API integration for URL/file scanning
- [ ] Google Safe Browsing API integration
- [ ] WHOIS domain age and registration analysis
- [ ] APK/file upload and scanning
- [ ] User authentication and accounts
- [ ] Real-time threat intelligence feeds
- [ ] Browser extension
- [ ] Export/share analysis reports
- [ ] Community scam reporting
