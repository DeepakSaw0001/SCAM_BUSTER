"""
ScamBuster Scan Repository

Handles persistence of scan results. Uses MongoDB Motor when connected,
falling back cleanly to an in-memory store so the application functions
reliably in all environments (local development, testing, and production).
"""

from typing import List, Optional
from app.database.mongodb import get_database
from app.schemas.scan import ScanResultResponse, ScanHistoryItem

# In-memory storage for resilient fallback
_IN_MEMORY_SCANS: List[ScanResultResponse] = []


async def save_scan_result(scan_result: ScanResultResponse) -> ScanResultResponse:
    """Save scan result to database or in-memory fallback."""
    # Always keep in memory for instant local retrieval
    _IN_MEMORY_SCANS.insert(0, scan_result)
    # Cap memory list at 200 items
    if len(_IN_MEMORY_SCANS) > 200:
        _IN_MEMORY_SCANS.pop()

    database = get_database()
    if database is not None:
        try:
            doc = scan_result.model_dump(mode="json")
            await database["scans"].insert_one(doc)
        except Exception:
            # Non-blocking fallback
            pass

    return scan_result


async def get_recent_scans(limit: int = 50) -> List[ScanHistoryItem]:
    """Retrieve recent scans summary."""
    database = get_database()
    if database is not None:
        try:
            cursor = database["scans"].find().sort("timestamp", -1).limit(limit)
            items = []
            async for doc in cursor:
                items.append(
                    ScanHistoryItem(
                        id=doc["id"],
                        scan_type=doc["scan_type"],
                        target=doc["target"],
                        timestamp=doc["timestamp"],
                        composite_risk_score=doc["composite_risk_score"],
                        risk_level=doc["risk_level"],
                        summary=doc["summary"],
                    )
                )
            if items:
                return items
        except Exception:
            pass

    # In-memory fallback
    return [
        ScanHistoryItem(
            id=s.id,
            scan_type=s.scan_type,
            target=s.target,
            timestamp=s.timestamp,
            composite_risk_score=s.composite_risk_score,
            risk_level=s.risk_level,
            summary=s.summary,
        )
        for s in _IN_MEMORY_SCANS[:limit]
    ]


async def get_scan_by_id(scan_id: str) -> Optional[ScanResultResponse]:
    """Retrieve full scan details by ID."""
    database = get_database()
    if database is not None:
        try:
            doc = await database["scans"].find_one({"id": scan_id})
            if doc:
                doc.pop("_id", None)
                return ScanResultResponse(**doc)
        except Exception:
            pass

    for s in _IN_MEMORY_SCANS:
        if s.id == scan_id:
            return s

    return None
