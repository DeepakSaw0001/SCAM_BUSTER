"""
ScamBuster — Open Threat Intelligence API Adapter (Phase 11)

Configurable external threat intelligence driver:
- Strictly optional, credentials configured solely via environment variables
- Guarded by SSRF checks, timeout limits, response size limits (512KB)
- Zero secret leakage in logs or reports
- Gracefully reports 'not_configured' when credentials are absent
"""

import logging
import os
import re
from typing import Any, Dict, Optional, Set
import urllib.parse

from app.intelligence.models import (
    FreshnessState,
    IndicatorType,
    IntelligenceStatus,
    IntelligenceVerdict,
    ThreatIndicator,
    ThreatIntelligenceReport,
)
from app.intelligence.providers.base import BaseThreatIntelProvider

logger = logging.getLogger("scambuster.intelligence.open_threat")

MAX_RESPONSE_BYTES = 512 * 1024  # 512 KB cap


class OpenThreatIntelProvider(BaseThreatIntelProvider):
    """
    Adapter for querying external REST threat intelligence APIs (e.g. URLhaus, AbuseIPDB).
    Safely disabled by default to ensure free/student/offline operation.
    """

    def __init__(
        self,
        name: str = "open-threat-api",
        endpoint: Optional[str] = None,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout_seconds: float = 3.0,
        rate_limit_rpm: int = 30,
        **kwargs,
    ):
        super().__init__(timeout_seconds=timeout_seconds, max_retries=1, rate_limit_rpm=rate_limit_rpm)
        self._name = name
        self._endpoint = api_url or endpoint or os.getenv("THREAT_INTEL_ENDPOINT", "").strip()
        self._api_key = api_key or os.getenv("THREAT_INTEL_API_KEY", "").strip()
        self._enabled = os.getenv("THREAT_INTEL_PROVIDER_ENABLED", "false").strip().lower() == "true"

    @property
    def name(self) -> str:
        return self._name

    @property
    def supported_indicator_types(self) -> Set[IndicatorType]:
        return {
            IndicatorType.URL,
            IndicatorType.DOMAIN,
            IndicatorType.IP,
            IndicatorType.FILE_HASH,
        }

    def is_configured(self) -> bool:
        return bool(self._endpoint and (self._enabled or self._api_key or "127.0.0.1" in self._endpoint or "localhost" in self._endpoint))

    async def _execute_lookup(self, indicator: ThreatIndicator) -> ThreatIntelligenceReport:
        import httpx

        # Validate endpoint against SSRF
        parsed = urllib.parse.urlsplit(self._endpoint)
        if parsed.hostname in ("localhost", "127.0.0.1", "::1") or parsed.scheme not in ("http", "https"):
            raise ValueError(f"Prohibited external threat endpoint: '{self._endpoint}'")

        if indicator.type == IndicatorType.IP and (indicator.metadata.get("is_bogon") or indicator.metadata.get("is_private")):
            raise ValueError(f"Prohibited external query for private or bogon IP: '{indicator.normalized_value}'")

        headers = {
            "User-Agent": "ScamBuster-Security-Research/1.0",
            "Authorization": f"Bearer {self._api_key}",
            "Accept": "application/json",
        }
        params = {
            "indicator_type": indicator.type.value,
            "indicator": indicator.normalized_value,
        }

        async with httpx.AsyncClient(timeout=self.timeout_seconds) as client:
            resp = await client.get(self._endpoint, params=params, headers=headers)
            if resp.status_code == 429:
                raise RuntimeError("External threat API rate limited (HTTP 429)")
            if resp.status_code >= 500:
                raise RuntimeError(f"External threat API service error (HTTP {resp.status_code})")
            if resp.status_code in (401, 403):
                raise RuntimeError("External threat API authentication failure (HTTP 401/403)")
            if resp.status_code != 200:
                return ThreatIntelligenceReport(
                    indicator=indicator,
                    provider=self.name,
                    status=IntelligenceStatus.AVAILABLE,
                    verdict=IntelligenceVerdict.UNKNOWN,
                    details={"http_status": resp.status_code},
                )

            # Cap content size
            if len(resp.content) > MAX_RESPONSE_BYTES:
                raise ValueError(f"Response size exceeded safety cap ({len(resp.content)} bytes)")

            data = resp.json()
            verdict_raw = str(data.get("verdict", "unknown")).lower()
            try:
                verdict = IntelligenceVerdict(verdict_raw)
            except ValueError:
                verdict = IntelligenceVerdict.UNKNOWN

            categories = data.get("categories", [])
            confidence = float(data.get("confidence", 0.7))
            ref_id = data.get("reference_id")

            # Sanitized details without credentials
            details = {
                "source": self.name,
                "threat_family": data.get("threat_family"),
                "first_seen": data.get("first_seen"),
                "last_seen": data.get("last_seen"),
            }

            return ThreatIntelligenceReport(
                indicator=indicator,
                provider=self.name,
                status=IntelligenceStatus.AVAILABLE,
                verdict=verdict,
                confidence=confidence,
                categories=categories,
                freshness=FreshnessState.RECENT,
                reference_id=ref_id,
                details=details,
            )
