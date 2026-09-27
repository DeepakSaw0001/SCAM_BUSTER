import logging
import re
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config.settings import settings

logger = logging.getLogger("scambuster.database")


class MongoDB:
    client: AsyncIOMotorClient = None
    database: AsyncIOMotorDatabase = None


db = MongoDB()


def _mask_mongo_uri(uri: str) -> str:
    """Mask credentials in MongoDB connection string for safe logging."""
    return re.sub(r"://([^:]+):([^@]+)@", r"://\1:****@", uri)


async def connect_to_mongo():
    """Establish async MongoDB connection."""
    if not settings.DATABASE_URL:
        raise ValueError("DATABASE_URL is not configured.")

    try:
        client = AsyncIOMotorClient(
            settings.DATABASE_URL,
            serverSelectionTimeoutMS=5000,
        )
        # Verify connection
        await client.admin.command("ping")
        db.client = client
        db.database = client[settings.DATABASE_NAME]
        safe_uri = _mask_mongo_uri(settings.DATABASE_URL)
        logger.info("[DB] Connected to MongoDB at %s (Database: %s)", safe_uri, settings.DATABASE_NAME)

        # Initialize collections & indexes
        from app.database.indexes import ensure_database_indexes
        await ensure_database_indexes(db.database)
    except Exception as e:
        db.client = None
        db.database = None
        logger.warning("[DB] MongoDB not reachable (%s). Backend running in offline/graceful mode.", e)


async def close_mongo_connection():
    """Close async MongoDB connection."""
    if db.client:
        db.client.close()
        logger.info("[DB] MongoDB connection closed.")


def get_database() -> AsyncIOMotorDatabase:
    """Return database reference for repositories."""
    return db.database
