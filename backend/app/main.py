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
        from app.ml.inference import get_model_manager
        from app.ml.message_inference import get_message_model_manager
        from app.ml.email_inference import EmailModelManager
        from app.ml.phone_inference import PhoneModelManager
        from app.ml.apk_inference import ApkModelManager
        from app.ml.apk_privacy_inference import ApkPrivacyModelManager
        from app.ml.web_inference import WebRiskModelManager
        get_model_manager()
        get_message_model_manager()
        EmailModelManager.get_instance()
        PhoneModelManager.get_instance()
        ApkModelManager.get_instance()
        ApkPrivacyModelManager.get_instance()
        WebRiskModelManager.get_instance()
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
        url_v1_ok = (MODELS_DIR / "url_model_v1.joblib").exists() or (Path(__file__).resolve().parent / "ml" / "models" / "url_model_v1.joblib").exists()
        msg_v1_ok = (MODELS_DIR / "message_model_v1.joblib").exists() or (Path(__file__).resolve().parent / "ml" / "models" / "message_model_v1.joblib").exists()

        return {
            "status": "healthy" if (url_v1_ok and msg_v1_ok) else "degraded",
            "service": "ScamBuster ML Service",
            "version": "1.0.0",
            "models": {
                "url_classifier": {
                    "available": url_v1_ok,
                    "artifact": "url_model_v1.joblib",
                    "version": "url-model-1.0",
                    "algorithm": "RandomForestClassifier",
                },
                "message_classifier": {
                    "available": msg_v1_ok,
                    "artifact": "message_model_v1.joblib",
                    "version": "message-model-1.0",
                    "algorithm": "TF-IDF + Calibrated LinearSVC",
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
