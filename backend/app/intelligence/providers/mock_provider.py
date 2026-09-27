"""
ScamBuster — Mock Intelligence Provider for Testing (Phase 06)

Provides a controllable intelligence provider for automated tests and CI environments.
Guarantees zero network calls and allows injection of simulated provider states:
- available (reported scam, suspicious, neutral)
- rate_limited
- timeout
- error
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict, Optional

from app.intelligence.base import PhoneIntelligenceProvider, PhoneIntelligenceResult
from app.services.phone_normalizer import NormalizedPhone


class MockPhoneIntelligenceProvider(PhoneIntelligenceProvider):
    def __init__(
        self,
        name: str = "mock-intel-provider",
        configured: bool = True,
        simulate_timeout: bool = False,
        simulate_rate_limit: bool = False,
        simulate_error: bool = False,
        preset_reputations: Optional[Dict[str, PhoneIntelligenceResult]] = None,
    ):
        self._name = name
        self._configured = configured
        self.simulate_timeout = simulate_timeout
        self.simulate_rate_limit = simulate_rate_limit
        self.simulate_error = simulate_error
        self.preset_reputations = preset_reputations or {}

    @property
    def name(self) -> str:
        return self._name

    def is_configured(self) -> bool:
        return self._configured

    async def lookup(self, phone: NormalizedPhone) -> PhoneIntelligenceResult:
        if not self._configured:
            return PhoneIntelligenceResult(
                provider=self._name,
                status="not_configured",
                reputation="unknown",
            )

        if self.simulate_timeout:
            await asyncio.sleep(0.01)
            return PhoneIntelligenceResult(
                provider=self._name,
                status="timeout",
                reputation="unknown",
                error_message="Provider timed out after 3.0s",
            )

        if self.simulate_rate_limit:
            return PhoneIntelligenceResult(
                provider=self._name,
                status="rate_limited",
                reputation="unknown",
                error_message="Provider rate limit exceeded (HTTP 429)",
            )

        if self.simulate_error:
            return PhoneIntelligenceResult(
                provider=self._name,
                status="error",
                reputation="unknown",
                error_message="Provider internal service error (HTTP 500)",
            )

        # Check explicit presets by HMAC or E.164
        if phone.hmac_token in self.preset_reputations:
            return self.preset_reputations[phone.hmac_token]

        if phone.e164 in self.preset_reputations:
            return self.preset_reputations[phone.e164]

        # Default neutral/unknown response
        return PhoneIntelligenceResult(
            provider=self._name,
            status="available",
            reputation="unknown",
            country=phone.region_code,
            number_type=phone.number_type_name.lower(),
            details={"note": "No previous community reports found in mock database"},
        )
