"""
ScamBuster — Centralized Privacy-Aware Intelligence Cache (Phase 11)

Provides:
- Indicator-specific TTL policies (URL: 30m, DOMAIN: 1h, IP: 1h, HASH: 24h, PHONE: 30m)
- Privacy-preserving hashed cache keys
- Zero storage of raw PII, sensitive message bodies, or auth tokens
- In-flight request deduplication via asyncio.Lock
- Safe operational metrics (requests, hits, misses, hit_rate, evictions)
- Automatic pruning of expired entries
"""

import asyncio
from datetime import datetime, timezone
import hashlib
import logging
import time
from typing import Any, Dict, List, Optional, Tuple

from app.intelligence.models import (
    FreshnessState,
    IndicatorType,
    ThreatIndicator,
    ThreatIntelligenceReport,
)

logger = logging.getLogger("scambuster.intelligence.cache")

# Default TTL policies (in seconds)
DEFAULT_TTL_POLICIES: Dict[IndicatorType, int] = {
    IndicatorType.URL: 1800,        # 30 minutes
    IndicatorType.DOMAIN: 3600,     # 1 hour
    IndicatorType.IP: 3600,         # 1 hour
    IndicatorType.FILE_HASH: 86400, # 24 hours (immutable cryptographic hash)
    IndicatorType.PHONE: 1800,      # 30 minutes
    IndicatorType.EMAIL: 3600,      # 1 hour
    IndicatorType.ASN: 86400,       # 24 hours
}

MAX_CACHE_ENTRIES = 20000


class IntelligenceCache:
    """
    In-memory, thread-safe asynchronous cache for threat intelligence reports.
    """

    def __init__(
        self,
        ttl_policies: Optional[Dict[IndicatorType, int]] = None,
        max_entries: int = MAX_CACHE_ENTRIES,
        **kwargs,
    ):
        self._ttl_policies = ttl_policies or dict(DEFAULT_TTL_POLICIES)
        self._max_entries = max_entries
        # Map: cache_key -> (Any, stored_timestamp, expires_timestamp)
        self._store: Dict[str, Tuple[Any, float, float]] = {}
        # In-flight locks for request collapsing
        self._inflight_locks: Dict[str, asyncio.Lock] = {}
        self._lock = asyncio.Lock()

        # Operational telemetry metrics
        self._requests = 0
        self._hits = 0
        self._misses = 0
        self._evictions = 0

    def compute_cache_key(self, indicator: ThreatIndicator) -> str:
        """
        Produce a deterministic, privacy-preserving SHA-256 cache key.
        Never stores cleartext PII in keys.
        """
        raw = f"{indicator.type.value}:{indicator.normalized_value}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def get_ttl_for_indicator(self, indicator_type: IndicatorType) -> int:
        return self._ttl_policies.get(indicator_type, 1800)

    async def get(self, indicator: ThreatIndicator) -> Optional[Any]:
        """
        Retrieve cached intelligence reports if not expired.
        Updates freshness state to 'CACHED' and annotates data age.
        """
        async with self._lock:
            self._requests += 1
            key = self.compute_cache_key(indicator)
            entry = self._store.get(key)
            if not entry:
                self._misses += 1
                return None

            data, stored_at, expires_at = entry
            now = time.time()

            if now > expires_at:
                # Expired
                del self._store[key]
                self._evictions += 1
                self._misses += 1
                return None

            self._hits += 1
            age_seconds = int(now - stored_at)

            from app.intelligence.models import CorrelatedIntelligenceResult
            if isinstance(data, CorrelatedIntelligenceResult):
                return data

            if isinstance(data, list):
                # Return deep-copied / updated reports with CACHED status
                refreshed: List[ThreatIntelligenceReport] = []
                for r in data:
                    refreshed.append(
                        ThreatIntelligenceReport(
                            indicator=indicator,
                            provider=r.provider,
                            status=r.status,
                            verdict=r.verdict,
                            confidence=r.confidence,
                            categories=list(r.categories),
                            checked_at=r.checked_at,
                            freshness=FreshnessState.CACHED,
                            data_age_seconds=age_seconds,
                            reference_id=r.reference_id,
                            details=dict(r.details),
                            error_message=r.error_message,
                        )
                    )
                return refreshed

            return data

    async def set(
        self,
        indicator: ThreatIndicator,
        reports: Any,
        custom_ttl: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """
        Store intelligence reports for an indicator with specified TTL.
        """
        async with self._lock:
            key = self.compute_cache_key(indicator)
            effective_ttl = ttl_seconds if ttl_seconds is not None else custom_ttl
            ttl = effective_ttl if effective_ttl is not None else self.get_ttl_for_indicator(indicator.type)
            now = time.time()
            expires_at = now + ttl

            # Capacity guard
            if len(self._store) >= self._max_entries:
                self._prune_expired_locked(now)
                if len(self._store) >= self._max_entries:
                    # Drop oldest entry
                    oldest_key = min(self._store.keys(), key=lambda k: self._store[k][1])
                    del self._store[oldest_key]
                    self._evictions += 1

            self._store[key] = (reports, now, expires_at)

    def _prune_expired_locked(self, now: float) -> None:
        expired = [k for k, (_, _, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]
            self._evictions += 1

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()
            self._inflight_locks.clear()

    async def get_inflight_lock(self, indicator: ThreatIndicator) -> asyncio.Lock:
        """Provide a per-indicator lock for in-flight request collapsing."""
        key = self.compute_cache_key(indicator)
        async with self._lock:
            if key not in self._inflight_locks:
                self._inflight_locks[key] = asyncio.Lock()
            return self._inflight_locks[key]

    async def release_inflight_lock(self, indicator: ThreatIndicator) -> None:
        """Release per-indicator lock after lookup completion."""
        key = self.compute_cache_key(indicator)
        async with self._lock:
            if key in self._inflight_locks:
                del self._inflight_locks[key]

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational telemetry metrics without exposing cached data."""
        hit_rate = (self._hits / self._requests) if self._requests > 0 else 0.0
        return {
            "total_requests": self._requests,
            "hits": self._hits,
            "misses": self._misses,
            "cache_hits": self._hits,
            "cache_misses": self._misses,
            "hit_rate": round(hit_rate, 4),
            "evictions": self._evictions,
            "current_size": len(self._store),
            "max_size": MAX_CACHE_ENTRIES,
        }


# Backward/Testing Alias
ThreatIntelligenceCache = IntelligenceCache
