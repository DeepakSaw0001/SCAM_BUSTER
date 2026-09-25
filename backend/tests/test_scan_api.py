"""
Integration Tests for ScamBuster Scan API Endpoints
"""

import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_scan_url_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {"url": "http://192.168.1.100/secure-login/verify.php"}
        res = await client.post("/api/v1/scan/url", json=payload)
    
    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "url"
    assert data["target"] == payload["url"]
    assert "composite_risk_score" in data
    assert data["risk_level"] in ("SAFE", "SUSPICIOUS", "DANGEROUS")
    assert "indicators" in data
    assert "recommendations" in data
    assert data["ml_metadata"] is not None


@pytest.mark.asyncio
async def test_scan_text_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "text": "URGENT: Your bank account will be closed today. Send your OTP code right away.",
            "sender": "+1234567890"
        }
        res = await client.post("/api/v1/scan/text", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "text"
    assert data["composite_risk_score"] >= 50
    assert data["ml_metadata"] is not None


@pytest.mark.asyncio
async def test_scan_email_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "sender": "Chase Bank <fraud-prevention@free-mail.com>",
            "subject": "Urgent: Overdue Wire Transfer Payment",
            "body": "Your invoice payment is past due. Wire funds immediately.",
            "attachments": ["Invoice_3892.exe"]
        }
        res = await client.post("/api/v1/scan/email", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "email"
    assert data["composite_risk_score"] >= 70
    assert data["risk_level"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_scan_phone_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "phone_number": "+23276123456",
            "context": "IRS agent claiming immediate arrest warrant"
        }
        res = await client.post("/api/v1/scan/phone", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "phone"
    assert data["composite_risk_score"] >= 50


@pytest.mark.asyncio
async def test_scan_apk_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        payload = {
            "package_name": "com.update.service.android",
            "app_name": "System Security Updater",
            "permissions": [
                "android.permission.BIND_ACCESSIBILITY_SERVICE",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECEIVE_SMS",
                "android.permission.INTERNET"
            ]
        }
        res = await client.post("/api/v1/scan/apk", json=payload)

    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "apk"
    assert data["risk_level"] == "DANGEROUS"


@pytest.mark.asyncio
async def test_scan_history_and_get_by_id():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Create a scan
        payload = {"url": "https://trusted-bank.example.com"}
        res = await client.post("/api/v1/scan/url", json=payload)
        assert res.status_code == 200
        scan_id = res.json()["id"]

        # Fetch history
        history_res = await client.get("/api/v1/scan/history")
        assert history_res.status_code == 200
        history_list = history_res.json()
        assert len(history_list) > 0
        assert any(item["id"] == scan_id for item in history_list)

        # Fetch specific scan
        single_res = await client.get(f"/api/v1/scan/{scan_id}")
        assert single_res.status_code == 200
        assert single_res.json()["id"] == scan_id
