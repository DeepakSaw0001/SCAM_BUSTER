"""
ScamBuster User Authentication & Profile Endpoints

Provides REST API routes for user registration, credential authentication,
session validation, profile management, and password updates.
"""

from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status

from app.config.settings import settings
from app.core.deps import get_current_user
from app.core.security import (
    create_access_token,
    hash_password,
    verify_password,
)
from app.database.user_repository import (
    create_user,
    get_user_by_email,
    get_user_by_identifier,
    get_user_by_username,
    update_last_login,
    update_password,
    update_user_profile,
)
from app.schemas.auth import (
    AuthMessageResponse,
    PasswordChangeRequest,
    TokenResponse,
    UserLoginRequest,
    UserProfileUpdate,
    UserRegisterRequest,
    UserResponse,
)

router = APIRouter()


def _to_user_response(user: Dict[str, Any]) -> UserResponse:
    """Format user dictionary to Pydantic UserResponse."""
    return UserResponse(
        id=user["id"],
        email=user["email"],
        username=user.get("username"),
        full_name=user.get("full_name"),
        role=user.get("role", "user"),
        is_active=user.get("is_active", True),
        created_at=str(user.get("created_at", "")),
        last_login=str(user.get("last_login")) if user.get("last_login") else None,
    )


@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
async def register(payload: UserRegisterRequest):
    """
    Register a new user account with email and password.
    Returns signed JWT access token upon successful registration.
    """
    # 1. Check existing email
    existing_user = await get_user_by_email(payload.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email address already exists.",
        )

    # 2. Check existing username if supplied
    if payload.username:
        existing_username = await get_user_by_username(payload.username)
        if existing_username:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This username handle is already claimed. Please choose another.",
            )

    # 3. Hash password with bcrypt
    hashed_pwd = hash_password(payload.password)

    # 4. Persist to MongoDB
    user = await create_user(
        email=payload.email,
        hashed_password=hashed_pwd,
        full_name=payload.full_name,
        username=payload.username,
        role="user",
    )

    # 5. Issue JWT Access Token
    token = create_access_token(
        subject=user["id"],
        extra_claims={
            "email": user["email"],
            "role": user["role"],
        },
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_to_user_response(user),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Authenticate with email/username and password",
)
async def login(payload: UserLoginRequest):
    """
    Authenticate user credentials and issue signed JWT access token.
    Accepts either registered email or username identifier.
    """
    user = await get_user_by_identifier(payload.email)
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials. Please verify your email/username and password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated. Please contact security support.",
        )

    # Record login timestamp
    await update_last_login(user["id"])

    # Issue JWT token
    token = create_access_token(
        subject=user["id"],
        extra_claims={
            "email": user["email"],
            "role": user.get("role", "user"),
        },
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=_to_user_response(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
    summary="Retrieve authenticated user profile",
)
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Return profile attributes for currently authenticated session."""
    return _to_user_response(current_user)


@router.put(
    "/profile",
    response_model=UserResponse,
    summary="Update profile details",
)
async def update_profile(
    payload: UserProfileUpdate,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Update profile information (e.g. display name)."""
    updated_user = await update_user_profile(current_user["id"], payload.full_name)
    if not updated_user:
        raise HTTPException(status_code=404, detail="User not found")
    return _to_user_response(updated_user)


@router.post(
    "/change-password",
    response_model=AuthMessageResponse,
    summary="Change account password",
)
async def change_password(
    payload: PasswordChangeRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """Change account password after verifying existing password."""
    if not verify_password(payload.current_password, current_user.get("hashed_password", "")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password verification failed.",
        )

    new_hash = hash_password(payload.new_password)
    success = await update_password(current_user["id"], new_hash)
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update password.")

    return AuthMessageResponse(message="Password successfully updated.")


@router.post(
    "/logout",
    response_model=AuthMessageResponse,
    summary="Terminate session",
)
async def logout():
    """Client-side session termination endpoint."""
    return AuthMessageResponse(message="Session successfully terminated.")
