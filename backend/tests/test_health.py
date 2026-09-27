import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_health_check_endpoint():
    """Verify GET /api/v1/health returns 200, valid structure, and correct service name."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")

    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "service" in data
    assert data["status"] == "ok"
    assert data["service"] == "scambuster-api"


@pytest.mark.asyncio
async def test_root_endpoint():
    """Verify root endpoint responds with service info."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "online"
    assert data["service"] == "scambuster-api"


@pytest.mark.asyncio
async def test_root_ping_endpoint():
    """Verify GET and HEAD /ping return 200 for keep-alive cron jobs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test GET
        get_res = await client.get("/ping")
        assert get_res.status_code == 200
        data = get_res.json()
        assert data["status"] == "ok"
        assert data["message"] == "pong"
        assert "timestamp" in data

        # Test HEAD (commonly used by cron jobs and uptime monitors)
        head_res = await client.head("/ping")
        assert head_res.status_code == 200


@pytest.mark.asyncio
async def test_v1_ping_endpoint():
    """Verify GET /api/v1/ping returns 200."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/api/v1/ping")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ok"
        assert data["message"] == "pong"
