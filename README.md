# 🛡️ ScamBuster — AI-Powered Cybersecurity Scam & Threat Detection

ScamBuster is an advanced full-stack cybersecurity platform designed to detect and analyze scams, malicious links, phishing attempts, suspicious phone numbers, and APK malware using real-time machine learning inference and heuristic risk engines.

---

## 🏗️ Architecture Overview

The system consists of:
- **Frontend**: React 18, TypeScript, Tailwind CSS, Vite (`frontend/`)
- **Backend**: FastAPI (Python 3.10+ / 3.12), Motor, Scikit-learn, PyTorch/Joblib inference (`backend/`)
- **Database**: MongoDB (Local or MongoDB Atlas)
- **Containerization**: Docker & Docker Compose

---

## ⚡ Option 1: Quick Start with Docker (Recommended)

The fastest and easiest way to run the entire stack (Database, Backend API, and Frontend) is with Docker Compose:

### 1. Prerequisites
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running.

### 2. Clone the Repository
```bash
git clone https://github.com/your-username/SCAM_BUSTER.git
cd SCAM_BUSTER
```

### 3. Launch Services
```bash
docker-compose up --build
```

### 4. Access the Application
- **Frontend App**: [http://localhost:5173](http://localhost:5173)
- **Backend API Docs (Swagger UI)**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Backend Health Check**: [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health)

To stop the containers:
```bash
docker-compose down
```

---

## 💻 Option 2: Manual Local Setup (Development Mode)

If you are developing locally or don't want to use Docker, follow these steps:

### 📋 Prerequisites
Make sure you have the following installed:
1. **Node.js**: v18.0.0 or higher ([Download Node.js](https://nodejs.org/))
2. **Python**: v3.10, v3.11, or v3.12 ([Download Python](https://www.python.org/))
3. **MongoDB**:
   - [MongoDB Community Server](https://www.mongodb.com/try/download/community) installed and running locally on port `27017`, **OR**
   - A free cloud database cluster from [MongoDB Atlas](https://www.mongodb.com/cloud/atlas).
4. **Git**: Installed on your system.

---

### Step 1: Clone the Repository
```bash
git clone https://github.com/your-username/SCAM_BUSTER.git
cd SCAM_BUSTER
```

---

### Step 2: Configure Environment Variables

Create a `.env` file in the root directory (or inside `backend/`):

#### On Windows (PowerShell):
```powershell
Copy-Item .env.example .env
```

#### On Linux / macOS:
```bash
cp .env.example .env
```

Open `.env` and verify/adjust your settings:
```ini
APP_ENV=development
DATABASE_URL=mongodb://localhost:27017
DATABASE_NAME=scambuster
JWT_SECRET=scambuster-super-secret-jwt-key-32-chars-2026
CORS_ORIGINS=["http://localhost:5173","http://127.0.0.1:5173"]
VITE_API_URL=http://localhost:8000
```
> **Note**: If using MongoDB Atlas, replace `DATABASE_URL` with your Atlas connection string:
> `DATABASE_URL=mongodb+srv://<username>:<password>@cluster0.xxxx.mongodb.net/?retryWrites=true&w=majority`

---

### Step 3: Set Up and Run the Backend (FastAPI)

1. Open a terminal and navigate to the `backend` folder:
   ```bash
   cd backend
   ```

2. Create and activate a Python virtual environment:
   - **On Windows (PowerShell)**:
     ```powershell
     python -m venv venv
     .\venv\Scripts\Activate.ps1
     ```
     *(If script execution is disabled on Windows, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` first)*
   - **On macOS / Linux**:
     ```bash
     python3 -m venv venv
     source venv/bin/activate
     ```

3. Upgrade pip and install the dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

4. Start the FastAPI development server:
   ```bash
   uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
   ```

The backend server is now running at:
- **API Base**: `http://127.0.0.1:8000`
- **Interactive API Documentation**: `http://127.0.0.1:8000/docs`

---

### Step 4: Set Up and Run the Frontend (React + Vite)

1. Open a **new terminal** and navigate to the `frontend` folder:
   ```bash
   cd frontend
   ```

2. Install npm dependencies:
   ```bash
   npm install
   ```

3. Start the Vite development server:
   ```bash
   npm run dev
   ```

4. Open your browser and navigate to:
   ```
   http://localhost:5173
   ```

---

## 🧪 Testing the Setup

1. **Verify Backend Health**:
   Open [http://localhost:8000/api/v1/health](http://localhost:8000/api/v1/health) in your browser. You should see `{"status":"ok"}`.
2. **Interactive Swagger Docs**:
   Visit [http://localhost:8000/docs](http://localhost:8000/docs) to explore and test all API endpoints directly.
3. **Frontend Dashboard**:
   Open [http://localhost:5173](http://localhost:5173) to create an account, log in, and perform URL, message, email, or APK scans.

---

## 🛠️ Common Troubleshooting

| Issue | Cause | Solution |
| :--- | :--- | :--- |
| **`Connection refused` on MongoDB** | MongoDB service isn't running | Start local MongoDB (`mongod` / Windows Services) or provide an Atlas URI in `.env` |
| **`UnauthorizedAccess` on PowerShell** | Execution policy prevents activating venv | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| **CORS Errors in browser console** | Frontend port not in allowed origins | Verify `CORS_ORIGINS` in `.env` includes `http://localhost:5173` |
| **Missing Python packages** | Dependencies not installed in active venv | Make sure `venv` is activated (terminal prompt shows `(venv)`) before running `pip install -r requirements.txt` |
| **Port 8000 or 5173 already in use** | Another instance is already running | Terminate old processes or run uvicorn on `--port 8001` and update `VITE_API_URL` |

---

## 📜 License
This project is licensed under the MIT License.
