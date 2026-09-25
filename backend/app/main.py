from contextlib import asynccontextmanager
from fastapi import FastAPI
from app.config.settings import settings
from app.security.cors import setup_cors
from app.database.mongodb import connect_to_mongo, close_mongo_connection
from app.api.v1.api import api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application startup and shutdown events."""
    # Startup: Connect database
    await connect_to_mongo()
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

    return application


app = create_application()
