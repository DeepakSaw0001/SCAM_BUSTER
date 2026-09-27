"""
ScamBuster — Intelligence Provider Abstraction Base (Phase 06)

Defines the contract for external threat intelligence providers for phone reputation.
Enforces:
- Structured, normalized result schemas.
- Explicit status attribution ("available", "not_configured", "unavailable", "rate_limited", "timeout", "error").
- No fake/invented intelligence reports.
- Retention of source timestamp and provider identity.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.services.phone_normalizer import NormalizedPhone


@dataclass
class PhoneIntelligenceResult:
    provider: str
    status: str                                  # "available", "not_configured", "unavailable", "rate_limited", "timeout", "error"
    reputation: str = "unknown"                  # "reported_scam", "suspicious", "neutral", "unknown"
    report_count: Optional[int] = None           # Real count only; None if provider does not furnish
    number_type: Optional[str] = None
    country: Optional[str] = None
    carrier: Optional[str] = None
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert intelligence result to a JSON-serializable dictionary."""
        d = {
            "provider": self.provider,
            "status": self.status,
            "reputation": self.reputation,
            "checked_at": self.checked_at,
        }
        if self.report_count is not None:
            d["report_count"] = self.report_count
        if self.number_type:
            d["number_type"] = self.number_type
        if self.country:
            d["country"] = self.country
        if self.carrier:
            d["carrier"] = self.carrier
        if self.details:
            d["details"] = self.details
        if self.error_message:
            d["error_message"] = self.error_message
        return d


class PhoneIntelligenceProvider(ABC):
    """Abstract interface for all phone intelligence providers."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the intelligence provider."""
        pass

    @abstractmethod
    def is_configured(self) -> bool:
        """Return True if required API credentials/configurations are present."""
        pass

    @abstractmethod
    async def lookup(self, phone: NormalizedPhone) -> PhoneIntelligenceResult:
        """
        Query provider for reputation intelligence on a normalized phone number.
        Must catch internal errors and return an appropriate PhoneIntelligenceResult
        with status 'unavailable', 'timeout', or 'error', rather than raising unhandled exceptions.
        """
        pass
