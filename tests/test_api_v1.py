"""
ScamBuster Root Test Suite — Phase 01 Verification
"""

import sys
from pathlib import Path
import pytest
from httpx import ASGITransport, AsyncClient

# Add backend to path
BACKEND_ROOT = Path(__file__).resolve().parent.parent / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.main import app


@pytest.mark.asyncio
async def test_api_v1_health():
    """Verify Phase 01 base health check endpoint contract."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    payload = response.json()
    assert payload == {"status": "ok", "service": "scambuster-api"}


@pytest.mark.asyncio
async def test_openapi_docs_available():
    """Verify OpenAPI documentation is accessible in development."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/openapi.json")

    assert response.status_code == 200
    data = response.json()
    assert "paths" in data
    assert "/api/v1/health" in data["paths"]
