"""
ScamBuster — APK Threat Intelligence Service & Abstraction (Phase 07)

Manages external APK reputation lookups (hash-based, package reputation) with:
- Privacy-safe hash querying (SHA-256 hash lookup, never uploading whole APKs)
- In-memory TTL caching (default 300 seconds)
- In-flight request deduplication
- Zero fake data: status is 'not_configured' when credentials are absent
- Non-blocking error handling to ensure static analysis always succeeds
"""

from abc import ABC, abstractmethod
import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import os
import time
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("scambuster.intelligence.apk")


@dataclass
class ApkIntelligenceResult:
    provider: str
    status: str                                  # "available", "not_configured", "unavailable", "rate_limited", "timeout", "error"
    reputation: str = "unknown"                  # "known_malware", "suspicious", "clean", "unknown"
    malware_family: Optional[str] = None
    detection_ratio: Optional[str] = None        # e.g. "18/70"
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "provider": self.provider,
            "status": self.status,
            "reputation": self.reputation,
            "checked_at": self.checked_at,
        }
        if self.malware_family:
            d["malware_family"] = self.malware_family
        if self.detection_ratio:
            d["detection_ratio"] = self.detection_ratio
        if self.details:
            d["details"] = self.details
        if self.error_message:
            d["error_message"] = self.error_message
        return d


class ApkIntelligenceProvider(ABC):
    """Abstract interface for all APK reputation providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        pass

    @abstractmethod
    async def lookup_by_hash(self, sha256_hash: str) -> ApkIntelligenceResult:
        pass


class MockApkIntelligenceProvider(ApkIntelligenceProvider):
    """Mock APK threat intelligence provider for testing."""

    def __init__(
        self,
        name: str = "mock-apk-intel",
        configured: bool = True,
        simulate_timeout: bool = False,
        simulate_rate_limit: bool = False,
        preset_hashes: Optional[Dict[str, ApkIntelligenceResult]] = None,
    ):
        self._name = name
        self._configured = configured
        self.simulate_timeout = simulate_timeout
        self.simulate_rate_limit = simulate_rate_limit
        self.preset_hashes = preset_hashes or {}

    @property
    def name(self) -> str:
        return self._name

    def is_configured(self) -> bool:
        return self._configured

    async def lookup_by_hash(self, sha256_hash: str) -> ApkIntelligenceResult:
        if not self._configured:
            return ApkIntelligenceResult(provider=self._name, status="not_configured", reputation="unknown")

        if self.simulate_timeout:
            await asyncio.sleep(0.01)
            return ApkIntelligenceResult(provider=self._name, status="timeout", reputation="unknown", error_message="Timed out")

        if self.simulate_rate_limit:
            return ApkIntelligenceResult(provider=self._name, status="rate_limited", reputation="unknown", error_message="Rate limit 429")

        if sha256_hash in self.preset_hashes:
            return self.preset_hashes[sha256_hash]

        return ApkIntelligenceResult(
            provider=self._name,
            status="available",
            reputation="unknown",
            details={"note": "No match found in mock malware database"},
        )


class ApkIntelligenceService:
    """Singleton service for managing APK threat intelligence lookups."""

    def __init__(self, provider: Optional[ApkIntelligenceProvider] = None, cache_ttl_seconds: int = 300):
        self._provider = provider
        self._cache_ttl = cache_ttl_seconds
        self._cache: Dict[str, Tuple[ApkIntelligenceResult, float]] = {}
        self._inflight_locks: Dict[str, asyncio.Lock] = {}
        self._init_provider()

    def _init_provider(self) -> None:
        if self._provider is not None:
            return

        provider_name = os.getenv("APK_INTELLIGENCE_PROVIDER", "").strip().lower()
        api_key = os.getenv("APK_INTELLIGENCE_API_KEY", "").strip()

        if not provider_name or provider_name in ("none", "disabled", "false"):
            self._provider = None
        elif provider_name == "mock":
            self._provider = MockApkIntelligenceProvider(
                configured=bool(api_key or os.getenv("MOCK_INTEL_ENABLED", "true").lower() == "true")
            )
        else:
            logger.warning("APK intelligence provider '%s' not enabled. Setting as not configured.", provider_name)
            self._provider = None

    def set_provider(self, provider: Optional[ApkIntelligenceProvider]) -> None:
        self._provider = provider
        self.clear_cache()

    def clear_cache(self) -> None:
        self._cache.clear()

    async def lookup(self, sha256_hash: str) -> ApkIntelligenceResult:
        if not sha256_hash or len(sha256_hash) != 64:
            return ApkIntelligenceResult(provider="none", status="not_configured", reputation="unknown")

        if self._provider is None or not self._provider.is_configured():
            return ApkIntelligenceResult(provider="none", status="not_configured", reputation="unknown")

        now = time.time()
        if sha256_hash in self._cache:
            res, ts = self._cache[sha256_hash]
            if now - ts < self._cache_ttl:
                return res

        lock = self._inflight_locks.setdefault(sha256_hash, asyncio.Lock())
        async with lock:
            if sha256_hash in self._cache:
                res, ts = self._cache[sha256_hash]
                if now - ts < self._cache_ttl:
                    return res

            try:
                result = await asyncio.wait_for(
                    self._provider.lookup_by_hash(sha256_hash),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                result = ApkIntelligenceResult(
                    provider=self._provider.name,
                    status="timeout",
                    reputation="unknown",
                    error_message="APK intelligence lookup timed out",
                )
            except Exception as e:
                result = ApkIntelligenceResult(
                    provider=self._provider.name,
                    status="error",
                    reputation="unknown",
                    error_message=str(e),
                )

            self._cache[sha256_hash] = (result, now)

        self._inflight_locks.pop(sha256_hash, None)
        return result


_apk_intel_service: Optional[ApkIntelligenceService] = None


def get_apk_intelligence_service() -> ApkIntelligenceService:
    global _apk_intel_service
    if _apk_intel_service is None:
        _apk_intel_service = ApkIntelligenceService()
    return _apk_intel_service
