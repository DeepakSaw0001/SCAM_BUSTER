"""
ScamBuster ML — FastAPI Inference Service

Endpoints:
    GET  /health          → service liveness + model availability
    POST /predict/text    → SMS/message spam classification
    POST /predict/url     → phishing URL classification

Start:
    cd ml/
    uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
"""

import sys
from pathlib import Path
from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Ensure project root is on the path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from inference.text_predictor import predict_text
from inference.url_predictor import predict_url
from utils.model_utils import MODELS_DIR

# ── app ──────────────────────────────────────────────────────────────────
app = FastAPI(
    title="ScamBuster ML Service",
    description=(
        "Machine-learning inference API for ScamBuster. "
        "Provides SMS spam classification and phishing URL detection. "
        "Predictions are statistical signals — they do NOT constitute "
        "proof that content is malicious."
    ),
    version="1.0.0",
)

# Allow the Node/Express backend to call us
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # tighten in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── request / response schemas ───────────────────────────────────────────
class TextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="The message text to classify")


class UrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="The URL to classify")


class TextResponse(BaseModel):
    prediction: str
    probability: float
    spam_probability: float
    model: str
    model_version: str
    preprocessed_input: str


class UrlResponse(BaseModel):
    prediction: str
    probability: float
    malicious_probability: float
    model: str
    model_version: str
    features_used: int
    extracted_features: dict


class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    models: dict
    timestamp: str


# ── routes ───────────────────────────────────────────────────────────────
@app.get("/")
def root():
    """Root info endpoint."""
    return {
        "service": "ScamBuster ML Service",
        "status": "online",
        "version": "1.0.0",
        "documentation": "/docs",
        "health": "/health",
        "endpoints": {
            "health": "GET /health",
            "predict_text": "POST /predict/text",
            "predict_url": "POST /predict/url",
        },
    }


@app.get("/health", response_model=HealthResponse)
def health():
    """Service liveness and model availability check."""
    text_model_ok = (MODELS_DIR / "text_classifier.joblib").exists()
    url_model_ok = (MODELS_DIR / "url_classifier.joblib").exists()

    return HealthResponse(
        status="healthy" if (text_model_ok and url_model_ok) else "degraded",
        service="ScamBuster ML Service",
        version="1.0.0",
        models={
            "text_classifier": {
                "available": text_model_ok,
                "artifact": "text_classifier.joblib",
                "algorithm": "TF-IDF + Logistic Regression",
            },
            "url_classifier": {
                "available": url_model_ok,
                "artifact": "url_classifier.joblib",
                "algorithm": "URL Features + Random Forest",
            },
        },
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@app.post("/predict/text", response_model=TextResponse)
def predict_text_endpoint(req: TextRequest):
    """Classify a message/SMS as ham or spam."""
    try:
        result = predict_text(req.text)
        return TextResponse(**result)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=503,
            detail=f"Text model not available. Train it first. ({e})",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")


@app.post("/predict/url", response_model=UrlResponse)
def predict_url_endpoint(req: UrlRequest):
    """Classify a URL as benign or malicious (phishing)."""
    try:
        result = predict_url(req.url)
        return UrlResponse(**result)
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=503,
            detail=f"URL model not available. Train it first. ({e})",
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {e}")
