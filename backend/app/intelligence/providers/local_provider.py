"""
ScamBuster — Local Feed Threat Intelligence Provider (Phase 11)

Queries the local verified threat feed catalog:
- 100% offline resilience (zero external network requests)
- High-fidelity curated intelligence for domains, hashes, URLs, phones, and IPs
- Complete provenance and reference retention
"""

from typing import Any, Optional, Set

from app.intelligence.feeds.catalog import get_local_feed_catalog
from app.intelligence.models import (
    FreshnessState,
    IndicatorType,
    IntelligenceStatus,
    IntelligenceVerdict,
    ThreatIndicator,
    ThreatIntelligenceReport,
)
from app.intelligence.providers.base import BaseThreatIntelProvider


class LocalFeedThreatProvider(BaseThreatIntelProvider):
    """
    Evaluates indicators against ScamBuster's verified local threat catalog.
    Always available, zero network latency.
    """

    def __init__(self, catalog: Optional[Any] = None, name: str = "scambuster-local-curated", **kwargs):
        super().__init__(timeout_seconds=0.5, max_retries=0, rate_limit_rpm=10000)
        self._name = name
        self._catalog = catalog or get_local_feed_catalog()

    @property
    def name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> Set[IndicatorType]:
        return {
            IndicatorType.DOMAIN,
            IndicatorType.URL,
            IndicatorType.FILE_HASH,
            IndicatorType.PHONE,
            IndicatorType.IP,
        }

    def is_configured(self) -> bool:
        return True

    async def _execute_lookup(self, indicator: ThreatIndicator) -> ThreatIntelligenceReport:
        record = self._catalog.lookup(indicator)
        if not record:
            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.AVAILABLE,
                verdict=IntelligenceVerdict.UNKNOWN,
                confidence=0.5,
                freshness=FreshnessState.RECENT,
                details={
                    "source": self._catalog.metadata.source,
                    "feed_version": self._catalog.metadata.version,
                    "matched": False,
                    "note": "No match found in local verified threat feed baseline.",
                },
            )

        return ThreatIntelligenceReport(
            indicator=indicator,
            provider=self.name,
            status=IntelligenceStatus.AVAILABLE,
            verdict=record.verdict,
            confidence=record.confidence,
            categories=list(record.categories),
            freshness=FreshnessState.RECENT,
            reference_id=record.reference_id,
            details={
                "source": self._catalog.metadata.source,
                "feed_version": self._catalog.metadata.version,
                "matched": True,
                "threat_actor_or_family": record.threat_actor_or_family,
                "description": record.description,
                "provenance": {
                    "license": self._catalog.metadata.license,
                    "retrieved_at": self._catalog.metadata.retrieved_at,
                },
            },
        )
