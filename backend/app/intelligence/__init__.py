"""
ScamBuster — Unified Threat Intelligence & Reputation Subsystem (Phase 11)
"""

from app.intelligence.models import (
    CorrelatedIntelligenceResult,
    FreshnessState,
    IndicatorType,
    IntelligenceStatus,
    IntelligenceVerdict,
    ThreatGraph,
    ThreatGraphEdge,
    ThreatGraphNode,
    ThreatIndicator,
    ThreatIntelligenceReport,
)
from app.intelligence.normalizer import (
    normalize_domain,
    normalize_email,
    normalize_file_hash,
    normalize_indicator,
    normalize_ip,
    normalize_url,
)
from app.intelligence.cache import IntelligenceCache
from app.intelligence.correlator import ThreatIntelligenceCorrelator
from app.intelligence.service import (
    ThreatIntelligenceService,
    get_threat_intelligence_service,
)

__all__ = [
    "IndicatorType",
    "IntelligenceVerdict",
    "IntelligenceStatus",
    "FreshnessState",
    "ThreatIndicator",
    "ThreatIntelligenceReport",
    "CorrelatedIntelligenceResult",
    "ThreatGraph",
    "ThreatGraphNode",
    "ThreatGraphEdge",
    "normalize_indicator",
    "normalize_domain",
    "normalize_url",
    "normalize_ip",
    "normalize_file_hash",
    "normalize_email",
    "IntelligenceCache",
    "ThreatIntelligenceCorrelator",
    "ThreatIntelligenceService",
    "get_threat_intelligence_service",
]
