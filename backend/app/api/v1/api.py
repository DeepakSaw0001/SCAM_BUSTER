from fastapi import APIRouter
from app.api.v1.endpoints import health, scan, chat, auth

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(scan.router)
api_router.include_router(chat.router, prefix="/chat", tags=["assistant"])
