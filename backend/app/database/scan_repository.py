"""
ScamBuster Scan Repository

Handles persistence of scan results in MongoDB with resilient in-memory fallback.
Supports user-specific history isolation and deletion.
"""

from typing import List, Optional
from app.database.mongodb import get_database
from app.schemas.scan import ScanResultResponse, ScanHistoryItem

# In-memory storage for resilient fallback
_IN_MEMORY_SCANS: List[ScanResultResponse] = []


async def save_scan_result(
    scan_result: ScanResultResponse,
    user_id: Optional[str] = None,
) -> ScanResultResponse:
    """Save scan result to MongoDB or in-memory fallback."""
    if user_id:
        scan_result.user_id = user_id

    # Always keep in memory for instant local retrieval
    _IN_MEMORY_SCANS.insert(0, scan_result)
    if len(_IN_MEMORY_SCANS) > 200:
        _IN_MEMORY_SCANS.pop()

    database = get_database()
    if database is not None:
        try:
            doc = scan_result.model_dump(mode="json")
            if user_id:
                doc["user_id"] = user_id
            await database["scans"].insert_one(doc)
        except Exception:
            pass

    return scan_result


async def get_recent_scans(
    limit: int = 50,
    user_id: Optional[str] = None,
) -> List[ScanHistoryItem]:
    """Retrieve recent scans summary, optionally filtered by user_id."""
    database = get_database()
    if database is not None:
        try:
            query = {}
            if user_id:
                query["user_id"] = user_id

            cursor = database["scans"].find(query).sort("timestamp", -1).limit(limit)
            items = []
            async for doc in cursor:
                items.append(
                    ScanHistoryItem(
                        id=doc["id"],
                        user_id=doc.get("user_id"),
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
    results = []
    for s in _IN_MEMORY_SCANS:
        if user_id and s.user_id != user_id:
            continue
        results.append(
            ScanHistoryItem(
                id=s.id,
                user_id=s.user_id,
                scan_type=s.scan_type,
                target=s.target,
                timestamp=s.timestamp,
                composite_risk_score=s.composite_risk_score,
                risk_level=s.risk_level,
                summary=s.summary,
            )
        )
        if len(results) >= limit:
            break

    return results


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


async def delete_scan(scan_id: str, user_id: Optional[str] = None) -> bool:
    """Delete a scan by ID, optionally requiring ownership by user_id."""
    global _IN_MEMORY_SCANS
    _IN_MEMORY_SCANS = [s for s in _IN_MEMORY_SCANS if s.id != scan_id]

    database = get_database()
    if database is not None:
        try:
            query = {"id": scan_id}
            if user_id:
                query["user_id"] = user_id
            res = await database["scans"].delete_one(query)
            return res.deleted_count > 0
        except Exception:
            pass

    return True
