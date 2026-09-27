"""
ScamBuster — Threat Intelligence & Reputation Models (Phase 11)

Defines standardized schemas for threat indicators, provider verdicts,
intelligence reports, multi-source correlation, and relationship graphs.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL = "email"
    PHONE = "phone"
    FILE_HASH = "file_hash"
    ASN = "asn"


class IntelligenceVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class IntelligenceStatus(str, Enum):
    AVAILABLE = "available"
    NOT_CONFIGURED = "not_configured"
    UNAVAILABLE = "unavailable"
    RATE_LIMITED = "rate_limited"
    TIMEOUT = "timeout"
    ERROR = "error"
    BLOCKED = "blocked"


class FreshnessState(str, Enum):
    RECENT = "recent"
    CACHED = "cached"
    STALE = "stale"
    UNKNOWN = "unknown"


@dataclass
class ThreatIndicator:
    """Normalized security indicator extracted from a scan target."""
    type: IndicatorType
    value: str
    normalized_value: str
    source: str = "scan_target"                  # e.g. "target", "embedded_link", "redirect_hop", "attachment_sha256", "sender_domain"
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "source": self.source,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "metadata": self.metadata,
        }


@dataclass
class ThreatIntelligenceReport:
    """Single intelligence verdict returned by an external or local provider."""
    indicator: ThreatIndicator
    provider: str
    status: IntelligenceStatus = IntelligenceStatus.AVAILABLE
    verdict: IntelligenceVerdict = IntelligenceVerdict.UNKNOWN
    confidence: float = 0.0                      # 0.0 - 1.0 provider-declared confidence
    categories: List[str] = field(default_factory=list)  # e.g. ["phishing", "malware", "scam"]
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    freshness: FreshnessState = FreshnessState.RECENT
    data_age_seconds: Optional[int] = 0
    reference_id: Optional[str] = None           # Optional incident/sample ID in provider database
    summary: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "indicator": self.indicator.to_dict(),
            "provider": self.provider,
            "status": self.status.value,
            "verdict": self.verdict.value,
            "confidence": round(self.confidence, 3),
            "categories": self.categories,
            "checked_at": self.checked_at,
            "freshness": self.freshness.value,
        }
        if self.data_age_seconds is not None:
            d["data_age_seconds"] = self.data_age_seconds
        if self.reference_id:
            d["reference_id"] = self.reference_id
        if self.details:
            d["details"] = self.details
        if self.error_message:
            d["error_message"] = self.error_message
        return d


@dataclass
class CorrelatedIntelligenceResult:
    """Multi-source corroborated intelligence for a specific indicator."""
    indicator: ThreatIndicator
    aggregate_verdict: IntelligenceVerdict = IntelligenceVerdict.UNKNOWN
    aggregate_confidence: float = 0.0
    is_corroborated: bool = False
    is_conflicting: bool = False
    reports: List[ThreatIntelligenceReport] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    provenance: List[Dict[str, Any]] = field(default_factory=list)
    summary_explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator.to_dict(),
            "aggregate_verdict": self.aggregate_verdict.value,
            "aggregate_confidence": round(self.aggregate_confidence, 3),
            "is_corroborated": self.is_corroborated,
            "is_conflicting": self.is_conflicting,
            "categories": self.categories,
            "reports_count": len(self.reports),
            "reports": [r.to_dict() for r in self.reports],
            "provenance": self.provenance,
            "summary_explanation": self.summary_explanation,
        }


@dataclass
class ThreatGraphNode:
    id: str
    type: str                                    # "target", "domain", "ip", "url", "file_hash", "phone", "email"
    label: str
    risk_level: str                              # "critical", "high", "medium", "low", "very_low", "unknown"
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "risk_level": self.risk_level,
            "details": self.details,
        }


@dataclass
class ThreatGraphEdge:
    source: str
    target: str
    relation: str                                # "RESOLVES_TO", "EMBEDS_URL", "DOWNLOADS_FILE", "REDIRECTS_TO", "CALLS_PHONE"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "relationship": self.relation,
        }


@dataclass
class ThreatGraph:
    nodes: List[ThreatGraphNode] = field(default_factory=list)
    edges: List[ThreatGraphEdge] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
        }
