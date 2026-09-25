from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI
from pydantic import BaseModel, Field

from app.config.settings import settings
from app.security.cors import setup_cors
from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.api.v1.api import api_router
from app.ml.client import analyze_text_ml, analyze_url_ml

MODELS_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"


class MLTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=5000, description="Message text to classify")


class MLUrlRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to classify")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown events."""
    # Startup: Connect database
    await connect_to_mongo()
    # Pre-warm ML models so first request is instant
    try:
        from app.ml.client import get_text_predictor, get_url_predictor
        get_text_predictor()
        get_url_predictor()
    except Exception:
        pass
    yield
    # Shutdown: Close database
    await close_mongo_connection()


def create_application() -> FastAPI:
    """FastAPI application factory."""
    application = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description="ScamBuster Backend API — Cybersecurity and AI Scam Detection Platform",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # Security: CORS
    setup_cors(application)

    # Routers
    application.include_router(api_router, prefix=settings.API_V1_PREFIX)

    @application.get("/", tags=["root"])
    async def root():
        return {
            "service": settings.PROJECT_NAME,
            "status": "online",
            "version": "1.0.0",
            "docs": "/docs",
            "health": f"{settings.API_V1_PREFIX}/health",
        }

    # Root ML Service Compatibility Routes (for ml/test_api_client.py and standalone clients)
    @application.get("/health", tags=["ml"])
    async def ml_health():
        text_model_ok = (MODELS_DIR / "text_classifier.joblib").exists()
        url_model_ok = (MODELS_DIR / "url_classifier.joblib").exists()

        return {
            "status": "healthy" if (text_model_ok and url_model_ok) else "degraded",
            "service": "ScamBuster ML Service",
            "version": "1.0.0",
            "models": {
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    @application.post("/predict/text", tags=["ml"])
    async def predict_text_route(req: MLTextRequest):
        return analyze_text_ml(req.text)

    @application.post("/predict/url", tags=["ml"])
    async def predict_url_route(req: MLUrlRequest):
        return analyze_url_ml(req.url)

    return application


app = create_application()
