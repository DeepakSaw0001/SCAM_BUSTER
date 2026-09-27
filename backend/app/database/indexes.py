"""
ScamBuster Database Index Management

Ensures optimal query performance, unique constraints, and schema
integrity for MongoDB collections (users, scans, threat intelligence).
"""

import logging
from motor.motor_asyncio import AsyncIOMotorDatabase
from pymongo import ASCENDING, DESCENDING, IndexModel

logger = logging.getLogger("scambuster.database.indexes")


async def ensure_database_indexes(database: AsyncIOMotorDatabase) -> None:
    """Create essential collections and indexes if not already present."""
    if database is None:
        return

    try:
        # 1. Users collection indexes
        users_col = database["users"]
        await users_col.create_indexes([
            IndexModel([("email", ASCENDING)], unique=True, name="idx_users_email_unique"),
            IndexModel([("username", ASCENDING)], unique=True, sparse=True, name="idx_users_username_unique"),
            IndexModel([("created_at", DESCENDING)], name="idx_users_created_at"),
        ])
        logger.info("[DB] Indexes verified for 'users' collection.")

        # 2. Scans collection indexes
        scans_col = database["scans"]
        await scans_col.create_indexes([
            IndexModel([("id", ASCENDING)], unique=True, name="idx_scans_id_unique"),
            IndexModel([("user_id", ASCENDING)], name="idx_scans_user_id"),
            IndexModel([("timestamp", DESCENDING)], name="idx_scans_timestamp"),
            IndexModel([("scan_type", ASCENDING)], name="idx_scans_type"),
        ])
        logger.info("[DB] Indexes verified for 'scans' collection.")

        # 3. Threat indicators cache collection
        intel_col = database["threat_indicators"]
        await intel_col.create_indexes([
            IndexModel([("normalized_value", ASCENDING)], name="idx_intel_value"),
            IndexModel([("indicator_type", ASCENDING)], name="idx_intel_type"),
            IndexModel([("cached_at", DESCENDING)], name="idx_intel_cached_at"),
        ])
        logger.info("[DB] Indexes verified for 'threat_indicators' collection.")

    except Exception as e:
        logger.warning("[DB] Failed to ensure database indexes: %s", e)
