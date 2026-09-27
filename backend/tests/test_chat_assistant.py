"""
ScamBuster AI Security Assistant — Integration Tests
"""

import pytest
from httpx import AsyncClient, ASGITransport

from app.main import app
from app.services.ai_assistant import get_ai_assistant_service
from app.schemas.chat import ChatRequest


@pytest.mark.asyncio
async def test_chat_starter_prompts():
    """Verify curated starter prompts endpoint returns list of security queries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/v1/chat/prompts")
    assert res.status_code == 200
    prompts = res.json()
    assert isinstance(prompts, list)
    assert len(prompts) >= 5
    assert any("OTP" in p for p in prompts)


@pytest.mark.asyncio
async def test_chat_triage_suspicious_text():
    """Verify chat endpoint evaluates urgency, OTP theft, and extracts URLs."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/chat",
            json={
                "message": "URGENT: Your account is suspended. Verify at http://192.168.1.1/login or share OTP"
            },
        )
    assert res.status_code == 200
    data = res.json()
    assert "reply" in data
    assert len(data["indicators"]) >= 1
    assert data["indicators"][0]["type"] == "url"
    assert "192.168.1.1" in data["indicators"][0]["value"]
    assert data["triage"] is not None
    assert data["triage"]["has_threat_detected"] is True
    assert len(data["suggested_actions"]) >= 1


@pytest.mark.asyncio
async def test_chat_emergency_incident():
    """Verify immediate containment protocol when a user indicates compromise."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/chat",
            json={
                "message": "Help, I gave my OTP to a caller and transferred money, what should I do?"
            },
        )
    assert res.status_code == 200
    data = res.json()
    assert any(w in data["reply"].lower() for w in ["freeze", "containment", "emergency", "bank", "compromised"])
    assert data["triage"]["risk_level"] == "CRITICAL"
    assert len(data["triage"]["emergency_actions"]) >= 3


@pytest.mark.asyncio
async def test_chat_educational_phishing_query():
    """Verify educational explanations for phishing queries."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/chat",
            json={"message": "Can you explain what phishing is and how to avoid it?"},
        )
    assert res.status_code == 200
    data = res.json()
    assert "phishing" in data["reply"].lower()
    assert len(data["suggested_prompts"]) >= 2


@pytest.mark.asyncio
async def test_chat_navigation_guidance():
    """Verify guidance on ScamBuster scanner capabilities."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/chat",
            json={"message": "How do I scan a phone number or use this platform?"},
        )
    assert res.status_code == 200
    data = res.json()
    assert any(w in data["reply"].lower() for w in ["scambuster", "scan", "link", "url", "phone", "apk"])
    assert any("/scan/phone" in a["target"] for a in data["suggested_actions"])


def test_assistant_indicator_extraction():
    """Test indicator extractor with URL, email, and phone."""
    service = get_ai_assistant_service()
    indicators = service.extract_indicators(
        "Call us at +1-800-555-0199 or email fraud@bank-alert.xyz or visit http://chase-update.top/login"
    )
    types = {ind.type for ind in indicators}
    assert "url" in types
    assert "email" in types
    assert "phone" in types
