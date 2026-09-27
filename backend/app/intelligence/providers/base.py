"""
ScamBuster — Unified Threat Intelligence Provider Abstraction (Phase 11)

Defines the contract for external and local threat intelligence providers:
- Enforces standardized ThreatIntelligenceReport return schema
- Built-in timeout guards (THREAT_INTEL_TIMEOUT_SECONDS)
- Bounded exponential backoff retries for transient errors
- Transparent status reporting (AVAILABLE, NOT_CONFIGURED, UNAVAILABLE, RATE_LIMITED, TIMEOUT, ERROR)
- Strict rate limiting and error encapsulation (never raises unhandled exceptions to callers)
"""

from abc import ABC, abstractmethod
import asyncio
import logging
import time
from typing import Any, Dict, Optional, Set

from app.intelligence.models import (
    FreshnessState,
    IndicatorType,
    IntelligenceStatus,
    IntelligenceVerdict,
    ThreatIndicator,
    ThreatIntelligenceReport,
)

logger = logging.getLogger("scambuster.intelligence.provider")


class BaseThreatIntelProvider(ABC):
    """
    Abstract Base Class for all Threat Intelligence Providers in ScamBuster.
    """

    def __init__(
        self,
        timeout_seconds: float = 3.0,
        max_retries: int = 2,
        rate_limit_rpm: int = 60,
    ):
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.rate_limit_rpm = rate_limit_rpm
        self._request_timestamps: list[float] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable provider identifier (e.g. 'local-threat-feed', 'mock-provider')."""
        pass

    @property
    @abstractmethod
    def supported_indicator_types(self) -> Set[IndicatorType]:
        """Set of indicator types this provider is capable of evaluating."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if credentials or required local datasets are loaded."""
        pass

    @abstractmethod
    async def _execute_lookup(self, indicator: ThreatIndicator) -> ThreatIntelligenceReport:
        """Internal lookup implementation to be overridden by subclasses."""
        pass

    def _check_rate_limit(self) -> bool:
        """Sliding window rate limit check. Returns True if request is permitted."""
        now = time.time()
        one_min_ago = now - 60.0
        self._request_timestamps = [t for t in self._request_timestamps if t > one_min_ago]
        if len(self._request_timestamps) >= self.rate_limit_rpm:
            return False
        self._request_timestamps.append(now)
        return True

    async def lookup(self, indicator: ThreatIndicator) -> ThreatIntelligenceReport:
        """
        Public entrypoint with safety rails:
        1. Checks configuration state
        2. Validates supported indicator type
        3. Enforces rate limits
        4. Applies timeout and retry backoff
        5. Encapsulates all exceptions
        """
        if not self.is_configured():
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.NOT_CONFIGURED,
                verdict=IntelligenceVerdict.UNKNOWN,
                details={"reason": "Provider is not configured or credentials are missing"},
            )

        if indicator.type not in self.supported_indicator_types:
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.NOT_CONFIGURED,
                verdict=IntelligenceVerdict.UNKNOWN,
                details={"reason": f"Indicator type '{indicator.type.value}' is not supported by {self.name}"},
            )

        if not self._check_rate_limit():
            logger.warning("Rate limit exceeded for provider '%s'", self.name)
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.RATE_LIMITED,
                verdict=IntelligenceVerdict.UNKNOWN,
                error_message=f"Local rate limit reached ({self.rate_limit_rpm} rpm) for {self.name}",
            )

        last_err: Optional[Exception] = None
        for attempt in range(self.max_retries + 1):
            try:
                report = await asyncio.wait_for(
                    self._execute_lookup(indicator),
                    timeout=self.timeout_seconds,
                )
                return report
            except asyncio.TimeoutError as te:
                last_err = te
                logger.warning(
                    "Provider '%s' timed out (attempt %d/%d) on indicator %s",
                    self.name, attempt + 1, self.max_retries + 1, indicator.normalized_value[:30]
                )
            except Exception as exc:
                last_err = exc
                err_str = str(exc).lower()
                if "429" in err_str or "rate limit" in err_str:
                    return ThreatIntelligenceReport(
                        indicator=indicator,
                        provider=self.name,
                        status=IntelligenceStatus.RATE_LIMITED,
                        verdict=IntelligenceVerdict.UNKNOWN,
                        error_message=f"External rate limit HTTP 429 encountered: {exc}",
                    )
                if "prohibited" in err_str or "blocked" in err_str or "ssrf" in err_str:
                    return ThreatIntelligenceReport(
                        indicator=indicator,
                        provider=self.name,
                        status=IntelligenceStatus.BLOCKED,
                        verdict=IntelligenceVerdict.UNKNOWN,
                        error_message=f"Request blocked by security guardrails: {exc}",
                    )
                logger.warning(
                    "Provider '%s' error (attempt %d/%d): %s",
                    self.name, attempt + 1, self.max_retries + 1, exc
                )

            if attempt < self.max_retries:
                backoff = min(0.15 * (2 ** attempt), 1.0)
                await asyncio.sleep(backoff)

        # Retries exhausted
        if isinstance(last_err, asyncio.TimeoutError):
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.TIMEOUT,
                verdict=IntelligenceVerdict.UNKNOWN,
                error_message=f"Provider timed out after {self.timeout_seconds}s across {self.max_retries + 1} attempts",
            )
        else:
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.ERROR,
                verdict=IntelligenceVerdict.UNKNOWN,
                error_message=f"Provider failed after {self.max_retries + 1} attempts: {last_err}",
            )
