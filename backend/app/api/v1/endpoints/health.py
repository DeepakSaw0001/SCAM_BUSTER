from fastapi import APIRouter
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Service Health Check")
async def health_check():
    """Return health status of the ScamBuster backend API."""
    return HealthResponse(status="ok", service="scambuster-api")
