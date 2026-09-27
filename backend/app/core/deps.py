"""
FastAPI Dependencies for Authentication & User Authorization

Provides dependency injection for requiring or optionally extracting
the authenticated user context from incoming JWT tokens.
"""

from typing import Any, Dict, Optional
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.core.security import decode_access_token
from app.database.user_repository import get_user_by_id

# Security scheme for Swagger UI & automated extraction
bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    """
    Validate Bearer token and retrieve active user.
    Raises HTTP 401 if token is missing, invalid, expired, or user is inactive.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials or session expired",
        headers={"WWW-Authenticate": "Bearer"},
    )

    if not credentials or not credentials.credentials:
        raise credentials_exception

    token = credentials.credentials
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise credentials_exception

    user_id = str(payload["sub"])
    user = await get_user_by_id(user_id)
    if not user:
        raise credentials_exception

    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return user


async def get_optional_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Optional[Dict[str, Any]]:
    """
    Optionally retrieve user context from token without blocking anonymous access.
    Returns None if no token or token is invalid.
    """
    if not credentials or not credentials.credentials:
        return None

    try:
        payload = decode_access_token(credentials.credentials)
        if not payload or not payload.get("sub"):
            return None

        user = await get_user_by_id(str(payload["sub"]))
        if user and user.get("is_active", True):
            return user
    except Exception:
        return None

    return None
