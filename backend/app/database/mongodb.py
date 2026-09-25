import logging
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from app.config.settings import settings

logger = logging.getLogger("scambuster.database")


class MongoDB:
    client: AsyncIOMotorClient = None
    database: AsyncIOMotorDatabase = None


db = MongoDB()


async def connect_to_mongo():
    """Establish async MongoDB connection."""
    if not settings.DATABASE_URL:
        raise ValueError("DATABASE_URL is not configured.")

    try:
        db.client = AsyncIOMotorClient(
            settings.DATABASE_URL,
            serverSelectionTimeoutMS=2000,
        )
        db.database = db.client[settings.DATABASE_NAME]
        # Verify connection
        await db.client.admin.command("ping")
        logger.info("[DB] Connected to MongoDB at %s (Database: %s)", settings.DATABASE_URL, settings.DATABASE_NAME)
    except Exception as e:
        logger.warning("[DB] MongoDB not reachable (%s). Backend running in offline/graceful mode.", e)


async def close_mongo_connection():
    """Close async MongoDB connection."""
    if db.client:
        db.client.close()
        logger.info("[DB] MongoDB connection closed.")


def get_database() -> AsyncIOMotorDatabase:
    """Return database reference for repositories."""
    return db.database
