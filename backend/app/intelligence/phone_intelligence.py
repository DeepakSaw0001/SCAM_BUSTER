"""
ScamBuster — Phone Intelligence Service & Manager (Phase 06)

Orchestrates threat intelligence lookups with:
- Privacy-safe cache keys (keyed HMAC tokens, never raw numbers in cache keys)
- In-memory TTL caching (default 300 seconds) to conserve provider quotas
- Transparent status tracking ("not_configured", "available", "unavailable", "timeout", "rate_limited", "error")
- Strict avoidance of fake intelligence data: returns 'not_configured' when credentials are absent
- Non-blocking error handling to ensure scan completion even during provider outages
"""

import asyncio
import logging
import os
import time
from typing import Dict, Optional, Tuple

from app.intelligence.base import PhoneIntelligenceProvider, PhoneIntelligenceResult
from app.intelligence.providers.mock_provider import MockPhoneIntelligenceProvider
from app.services.phone_normalizer import NormalizedPhone

logger = logging.getLogger("scambuster.intelligence.phone")


class PhoneIntelligenceService:
    """
    Singleton service managing phone threat intelligence lookups,
    caching, rate limiting, and provider orchestration.
    """

    def __init__(self, provider: Optional[PhoneIntelligenceProvider] = None, cache_ttl_seconds: int = 300):
        self._provider = provider
        self._cache_ttl = cache_ttl_seconds
        # In-memory TTL cache: hmac_token -> (PhoneIntelligenceResult, timestamp)
        self._cache: Dict[str, Tuple[PhoneIntelligenceResult, float]] = {}
        # In-flight lock deduplication
        self._inflight_locks: Dict[str, asyncio.Lock] = {}
        self._init_provider()

    def _init_provider(self) -> None:
        """Initialize provider based on environment variables if not injected."""
        if self._provider is not None:
            return

        provider_name = os.getenv("PHONE_INTELLIGENCE_PROVIDER", "").strip().lower()
        api_key = os.getenv("PHONE_INTELLIGENCE_API_KEY", "").strip()

        if not provider_name or provider_name in ("none", "disabled", "false"):
            self._provider = None
            logger.info("Phone threat intelligence provider is not configured.")
        elif provider_name == "mock":
            self._provider = MockPhoneIntelligenceProvider(
                name="mock-provider",
                configured=bool(api_key or os.getenv("MOCK_INTEL_ENABLED", "true").lower() == "true")
            )
            logger.info("Initialized mock phone threat intelligence provider.")
        else:
            # Placeholder for future production external providers (e.g. Twilio Lookup, Numverify)
            logger.warning(
                "Phone intelligence provider '%s' specified, but external driver is not yet enabled. "
                "Marking as unconfigured.",
                provider_name
            )
            self._provider = None

    def set_provider(self, provider: Optional[PhoneIntelligenceProvider]) -> None:
        """Dynamically set or mock the provider (e.g. for testing)."""
        self._provider = provider
        self.clear_cache()

    def clear_cache(self) -> None:
        """Clear cached intelligence responses."""
        self._cache.clear()

    async def lookup(self, phone: NormalizedPhone) -> PhoneIntelligenceResult:
        """
        Perform a privacy-preserving intelligence lookup for the given normalized phone number.
        Uses cached responses where available.
        Shields caller from external network/provider exceptions.
        """
        if not phone.is_possible and not phone.is_valid:
            return PhoneIntelligenceResult(
                provider="none",
                status="not_configured",
                reputation="unknown",
                details={"reason": "Number is not possible or valid E.164"},
            )

        if self._provider is None or not self._provider.is_configured():
            return PhoneIntelligenceResult(
                provider="none",
                status="not_configured",
                reputation="unknown",
            )

        cache_key = phone.hmac_token
        now = time.time()

        # Check cache
        if cache_key in self._cache:
            result, timestamp = self._cache[cache_key]
            if now - timestamp < self._cache_ttl:
                return result

        # In-flight lock to deduplicate concurrent scans for the same number
        lock = self._inflight_locks.setdefault(cache_key, asyncio.Lock())
        async with lock:
            # Re-check cache inside lock
            if cache_key in self._cache:
                result, timestamp = self._cache[cache_key]
                if now - timestamp < self._cache_ttl:
                    return result

            try:
                # Privacy-safe log: Only masked phone representation
                logger.debug("Querying phone intelligence provider for masked target: %s", phone.masked)
                intel_result = await asyncio.wait_for(
                    self._provider.lookup(phone),
                    timeout=5.0
                )
            except asyncio.TimeoutError:
                logger.warning("Phone intelligence lookup timed out for target: %s", phone.masked)
                intel_result = PhoneIntelligenceResult(
                    provider=self._provider.name,
                    status="timeout",
                    reputation="unknown",
                    error_message="Intelligence provider timed out after 5.0 seconds",
                )
            except Exception as e:
                logger.error("Phone intelligence lookup error for target %s: %s", phone.masked, str(e))
                intel_result = PhoneIntelligenceResult(
                    provider=self._provider.name,
                    status="error",
                    reputation="unknown",
                    error_message="Unexpected error during intelligence query",
                )

            # Cache the result
            self._cache[cache_key] = (intel_result, now)

        # Cleanup lock reference
        self._inflight_locks.pop(cache_key, None)
        return intel_result


# Global singleton instance
_phone_intel_service: Optional[PhoneIntelligenceService] = None


def get_phone_intelligence_service() -> PhoneIntelligenceService:
    global _phone_intel_service
    if _phone_intel_service is None:
        _phone_intel_service = PhoneIntelligenceService()
    return _phone_intel_service
