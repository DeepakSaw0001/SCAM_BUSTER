"""
Authentication & Authorization API Integration Tests

Validates user registration, password hashing, JWT token issuance,
session validation, profile updates, and credential verification.
"""

import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from app.main import app


@pytest.mark.asyncio
async def test_auth_full_lifecycle():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        unique_id = uuid.uuid4().hex[:8]
        test_email = f"analyst_{unique_id}@scambuster.test"
        test_username = f"analyst_{unique_id}"
        test_password = "SecurePassword123!"

        # 1. Register new user
        reg_res = await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_email,
                "username": test_username,
                "password": test_password,
                "full_name": "Senior Threat Analyst",
            },
        )
        assert reg_res.status_code == 201
        reg_data = reg_res.json()
        assert "access_token" in reg_data
        assert reg_data["token_type"] == "bearer"
        assert reg_data["user"]["email"] == test_email
        assert reg_data["user"]["username"] == test_username
        assert reg_data["user"]["full_name"] == "Senior Threat Analyst"
        token = reg_data["access_token"]

        # 2. Duplicate registration should fail
        dup_res = await client.post(
            "/api/v1/auth/register",
            json={
                "email": test_email,
                "password": "AnotherPassword456!",
            },
        )
        assert dup_res.status_code == 400

        # 3. Login with wrong password should fail
        bad_login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_email,
                "password": "WrongPassword!",
            },
        )
        assert bad_login.status_code == 401

        # 4. Login with correct email
        login_res = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_email,
                "password": test_password,
            },
        )
        assert login_res.status_code == 200
        login_token = login_res.json()["access_token"]

        # 5. Login with username instead of email
        user_login = await client.post(
            "/api/v1/auth/login",
            json={
                "email": test_username,
                "password": test_password,
            },
        )
        assert user_login.status_code == 200

        # 6. Access /me with Bearer token
        me_res = await client.get(
            "/api/v1/auth/me",
            headers={"Authorization": f"Bearer {login_token}"},
        )
        assert me_res.status_code == 200
        me_data = me_res.json()
        assert me_data["email"] == test_email
        assert me_data["full_name"] == "Senior Threat Analyst"

        # 7. Access /me without token should fail
        unauth_res = await client.get("/api/v1/auth/me")
        assert unauth_res.status_code == 401

        # 8. Update profile
        prof_res = await client.put(
            "/api/v1/auth/profile",
            headers={"Authorization": f"Bearer {login_token}"},
            json={"full_name": "Lead Security Engineer"},
        )
        assert prof_res.status_code == 200
        assert prof_res.json()["full_name"] == "Lead Security Engineer"

        # 9. Change password
        new_pwd = "BrandNewPassword789!"
        pwd_res = await client.post(
            "/api/v1/auth/change-password",
            headers={"Authorization": f"Bearer {login_token}"},
            json={
                "current_password": test_password,
                "new_password": new_pwd,
            },
        )
        assert pwd_res.status_code == 200

        # Verify old password fails
        old_fail = await client.post(
            "/api/v1/auth/login",
            json={"email": test_email, "password": test_password},
        )
        assert old_fail.status_code == 401

        # Verify new password succeeds
        new_ok = await client.post(
            "/api/v1/auth/login",
            json={"email": test_email, "password": new_pwd},
        )
        assert new_ok.status_code == 200
