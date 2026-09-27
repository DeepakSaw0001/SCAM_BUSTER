"""
Authentication & User Pydantic Schemas

Defines request/response contracts for user registration, authentication,
profile management, and JWT token exchange.
"""

import re
from typing import Optional
from pydantic import BaseModel, Field, field_validator


class UserRegisterRequest(BaseModel):
    """Payload for creating a new user account."""
    email: str = Field(..., description="Valid user email address", min_length=5, max_length=255)
    password: str = Field(..., description="Plaintext password", min_length=6, max_length=128)
    full_name: Optional[str] = Field(None, description="User's display or full name", max_length=120)
    username: Optional[str] = Field(None, description="Unique username handle", min_length=3, max_length=50)

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        clean = v.strip().lower()
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", clean):
            raise ValueError("Invalid email format")
        return clean

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip().lower()
        if not re.match(r"^[a-zA-Z0-9_\-\.]{3,50}$", clean):
            raise ValueError("Username must be 3-50 alphanumeric characters or hyphens/underscores")
        return clean


class UserLoginRequest(BaseModel):
    """Payload for user sign in."""
    email: str = Field(..., description="Email address or username")
    password: str = Field(..., description="User password")

    @field_validator("email")
    @classmethod
    def clean_identifier(cls, v: str) -> str:
        return v.strip().lower()


class UserProfileUpdate(BaseModel):
    """Payload for updating user profile."""
    full_name: Optional[str] = Field(None, max_length=120)
    avatar_url: Optional[str] = Field(None, max_length=512)


class PasswordChangeRequest(BaseModel):
    """Payload for changing account password."""
    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=6, max_length=128)


class UserResponse(BaseModel):
    """Public user profile data."""
    id: str
    email: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: str = "user"
    is_active: bool = True
    created_at: str
    last_login: Optional[str] = None


class TokenResponse(BaseModel):
    """JWT authentication response with user context."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class AuthMessageResponse(BaseModel):
    """Standard message response for auth operations."""
    message: str
    success: bool = True
