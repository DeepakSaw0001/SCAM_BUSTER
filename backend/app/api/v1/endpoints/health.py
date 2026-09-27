from fastapi import APIRouter
from app.schemas.health import HealthResponse

router = APIRouter()


@router.get("/health", response_model=HealthResponse, summary="Service Health Check")
async def health_check():
    """Return health status of the ScamBuster backend API."""
    return HealthResponse(status="ok", service="scambuster-api")


@router.get("/ping", summary="Keep-alive ping endpoint for cron jobs")
@router.head("/ping", include_in_schema=False)
async def ping():
    """Return fast keep-alive ping for external uptime checkers and cron-jobs."""
    return {"status": "ok", "message": "pong"}
