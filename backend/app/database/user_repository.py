"""
ScamBuster User Repository

Handles persistence and retrieval of user accounts using MongoDB Motor
with resilient in-memory caching and offline fallback.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from app.database.mongodb import get_database

# In-memory user store for graceful offline fallback and tests
_IN_MEMORY_USERS: Dict[str, Dict[str, Any]] = {}


def _serialize_doc(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure MongoDB document is JSON-friendly."""
    clean = dict(doc)
    clean.pop("_id", None)
    return clean


async def create_user(
    email: str,
    hashed_password: str,
    full_name: Optional[str] = None,
    username: Optional[str] = None,
    role: str = "user",
) -> Dict[str, Any]:
    """Create and persist a new user record."""
    user_id = f"usr_{uuid.uuid4().hex[:16]}"
    now = datetime.now(timezone.utc).isoformat()

    user_doc = {
        "id": user_id,
        "email": email.strip().lower(),
        "username": username.strip().lower() if username else None,
        "hashed_password": hashed_password,
        "full_name": full_name.strip() if full_name else None,
        "role": role,
        "is_active": True,
        "created_at": now,
        "updated_at": now,
        "last_login": None,
    }

    # Store in memory fallback
    _IN_MEMORY_USERS[user_id] = dict(user_doc)

    # Store in MongoDB
    database = get_database()
    if database is not None:
        try:
            await database["users"].insert_one(dict(user_doc))
        except Exception:
            pass

    return _serialize_doc(user_doc)


async def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    """Find a user by normalized email address."""
    clean_email = email.strip().lower()
    database = get_database()
    if database is not None:
        try:
            doc = await database["users"].find_one({"email": clean_email})
            if doc:
                return _serialize_doc(doc)
        except Exception:
            pass

    # Fallback to in-memory
    for user in _IN_MEMORY_USERS.values():
        if user.get("email") == clean_email:
            return _serialize_doc(user)

    return None


async def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Find a user by username."""
    clean_username = username.strip().lower()
    database = get_database()
    if database is not None:
        try:
            doc = await database["users"].find_one({"username": clean_username})
            if doc:
                return _serialize_doc(doc)
        except Exception:
            pass

    for user in _IN_MEMORY_USERS.values():
        if user.get("username") == clean_username:
            return _serialize_doc(user)

    return None


async def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Find a user by their unique ScamBuster ID."""
    database = get_database()
    if database is not None:
        try:
            doc = await database["users"].find_one({"id": user_id})
            if doc:
                return _serialize_doc(doc)
        except Exception:
            pass

    user = _IN_MEMORY_USERS.get(user_id)
    if user:
        return _serialize_doc(user)

    return None


async def get_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    """Find user by email or username."""
    clean = identifier.strip().lower()
    user = await get_user_by_email(clean)
    if not user:
        user = await get_user_by_username(clean)
    return user


async def update_last_login(user_id: str) -> None:
    """Record timestamp of successful authentication."""
    now = datetime.now(timezone.utc).isoformat()
    if user_id in _IN_MEMORY_USERS:
        _IN_MEMORY_USERS[user_id]["last_login"] = now

    database = get_database()
    if database is not None:
        try:
            await database["users"].update_one(
                {"id": user_id},
                {"$set": {"last_login": now}}
            )
        except Exception:
            pass


async def update_user_profile(user_id: str, full_name: Optional[str]) -> Optional[Dict[str, Any]]:
    """Update profile attributes for a user."""
    now = datetime.now(timezone.utc).isoformat()
    updates = {"updated_at": now}
    if full_name is not None:
        updates["full_name"] = full_name.strip()

    if user_id in _IN_MEMORY_USERS:
        _IN_MEMORY_USERS[user_id].update(updates)

    database = get_database()
    if database is not None:
        try:
            await database["users"].update_one(
                {"id": user_id},
                {"$set": updates}
            )
            doc = await database["users"].find_one({"id": user_id})
            if doc:
                return _serialize_doc(doc)
        except Exception:
            pass

    user = _IN_MEMORY_USERS.get(user_id)
    return _serialize_doc(user) if user else None


async def update_password(user_id: str, new_hashed_password: str) -> bool:
    """Update password hash for a user."""
    now = datetime.now(timezone.utc).isoformat()
    if user_id in _IN_MEMORY_USERS:
        _IN_MEMORY_USERS[user_id]["hashed_password"] = new_hashed_password
        _IN_MEMORY_USERS[user_id]["updated_at"] = now

    database = get_database()
    if database is not None:
        try:
            result = await database["users"].update_one(
                {"id": user_id},
                {"$set": {"hashed_password": new_hashed_password, "updated_at": now}}
            )
            return result.modified_count > 0
        except Exception:
            pass

    return user_id in _IN_MEMORY_USERS
