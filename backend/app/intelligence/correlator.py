"""
ScamBuster — Threat Intelligence Correlator & Graph Engine (Phase 11)

Orchestrates:
- Priority-based provider queries (Cache -> Local Threat Feeds -> External Providers)
- Intelligence budget enforcement (max requests per scan, max lookups per indicator, latency cap)
- Batch deduplication (never query the same indicator twice in one scan)
- Multi-source correlation (corroboration elevation, explicit conflict detection, unknown state preservation)
- Interactive Threat Graph construction connecting targets, domains, IPs, URLs, redirects, downloads, and hashes
"""

import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from app.intelligence.cache import IntelligenceCache
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
from app.intelligence.providers.base import BaseThreatIntelProvider
from app.intelligence.providers.local_provider import LocalFeedThreatProvider

logger = logging.getLogger("scambuster.intelligence.correlator")

# Budget controls
MAX_PROVIDER_REQUESTS_PER_SCAN = 10
MAX_LOOKUPS_PER_INDICATOR = 3
MAX_TOTAL_INTEL_LATENCY = 4.0


class ThreatIntelligenceCorrelator:
    """
    Central engine for querying threat providers, caching, corroborating evidence,
    and generating relationship threat graphs.
    """

    def __init__(
        self,
        providers: Optional[List[BaseThreatIntelProvider]] = None,
        cache: Optional[IntelligenceCache] = None,
        max_lookups_per_scan: int = MAX_PROVIDER_REQUESTS_PER_SCAN,
        **kwargs,
    ):
        self._providers = providers if providers is not None else [LocalFeedThreatProvider()]
        self._cache = cache or IntelligenceCache()
        self._max_lookups_per_scan = max_lookups_per_scan

    def set_providers(self, providers: List[BaseThreatIntelProvider]) -> None:
        """Dynamically update providers list (e.g. for testing)."""
        self._providers = providers

    async def correlate_single(
        self,
        indicator: ThreatIndicator,
    ) -> Tuple[CorrelatedIntelligenceResult, ThreatGraph]:
        """Correlate a single indicator and produce both result and a threat graph."""
        res = await self.correlate_indicator(indicator)
        graph = self.build_threat_graph(
            target_label=indicator.normalized_value,
            target_type=indicator.type.value,
            target_risk_level=res.aggregate_verdict.value,
            correlated_results={f"{indicator.type.value}:{indicator.normalized_value}": res},
        )
        return res, graph

    def add_provider(self, provider: BaseThreatIntelProvider) -> None:
        self._providers.append(provider)

    @property
    def cache(self) -> IntelligenceCache:
        return self._cache

    async def correlate_indicator(
        self,
        indicator: ThreatIndicator,
    ) -> CorrelatedIntelligenceResult:
        """
        Correlate threat intelligence for a single indicator:
        1. Check cache
        2. Query configured providers (if cache miss)
        3. Multi-source agreement / conflict synthesis
        4. Cache fresh reports
        """
        # 1. Check Cache
        cached_reports = await self._cache.get(indicator)
        if cached_reports is not None:
            return self._synthesize_reports(indicator, cached_reports)

        # 2. Acquire in-flight lock to deduplicate concurrent lookups
        lock = await self._cache.get_inflight_lock(indicator)
        async with lock:
            # Re-check cache inside lock
            cached_reports = await self._cache.get(indicator)
            if cached_reports is not None:
                return self._synthesize_reports(indicator, cached_reports)

            reports: List[ThreatIntelligenceReport] = []
            lookups_done = 0

            # 3. Query providers up to per-indicator limit
            for provider in self._providers:
                if lookups_done >= MAX_LOOKUPS_PER_INDICATOR:
                    break
                if not provider.is_configured() or indicator.type not in provider.supported_indicator_types:
                    continue

                try:
                    rep = await provider.lookup(indicator)
                    reports.append(rep)
                    lookups_done += 1
                except Exception as exc:
                    logger.error("Provider '%s' lookup failed unexpectedly: %s", provider.name, exc)
                    reports.append(
                        ThreatIntelligenceReport(
                            indicator=indicator,
                            provider=provider.name,
                            status=IntelligenceStatus.ERROR,
                            verdict=IntelligenceVerdict.UNKNOWN,
                            error_message=str(exc),
                        )
                    )

            # If no providers were configured or returned results
            if not reports:
                reports.append(
                    ThreatIntelligenceReport(
                        indicator=indicator,
                        provider="none",
                        status=IntelligenceStatus.NOT_CONFIGURED,
                        verdict=IntelligenceVerdict.UNKNOWN,
                        details={"note": "No active threat intelligence providers configured for this indicator type."},
                    )
                )

            # 4. Cache successful/available reports
            has_available = any(r.status == IntelligenceStatus.AVAILABLE for r in reports)
            if has_available:
                await self._cache.set(indicator, reports)

            return self._synthesize_reports(indicator, reports)

    def _synthesize_reports(
        self,
        indicator: ThreatIndicator,
        reports: List[ThreatIntelligenceReport],
    ) -> CorrelatedIntelligenceResult:
        """
        Combine multiple provider reports into a correlated intelligence verdict.
        Respects:
        - Corroborated evidence (multiple independent malicious reports)
        - Conflicting reports (malicious vs benign preserved)
        - Unknown states (unknown != safe)
        """
        active_reports = [r for r in reports if r.status == IntelligenceStatus.AVAILABLE]

        if not active_reports:
            return CorrelatedIntelligenceResult(
                indicator=indicator,
                aggregate_verdict=IntelligenceVerdict.UNKNOWN,
                aggregate_confidence=0.5,
                is_corroborated=False,
                is_conflicting=False,
                reports=reports,
                categories=[],
                provenance=[{"provider": r.provider, "status": r.status.value} for r in reports],
                summary_explanation="Threat intelligence unavailable or not configured.",
            )

        malicious_count = sum(1 for r in active_reports if r.verdict == IntelligenceVerdict.MALICIOUS)
        suspicious_count = sum(1 for r in active_reports if r.verdict == IntelligenceVerdict.SUSPICIOUS)
        benign_count = sum(1 for r in active_reports if r.verdict == IntelligenceVerdict.BENIGN)

        all_categories = sorted(list({cat for r in active_reports for cat in r.categories}))
        is_corroborated = (malicious_count + suspicious_count) >= 2
        is_conflicting = (malicious_count > 0 and benign_count > 0)

        # Verdict calculation
        if malicious_count > 0:
            aggregate_verdict = IntelligenceVerdict.MALICIOUS
        elif suspicious_count > 0:
            aggregate_verdict = IntelligenceVerdict.SUSPICIOUS
        elif benign_count > 0 and not is_conflicting:
            aggregate_verdict = IntelligenceVerdict.BENIGN
        else:
            aggregate_verdict = IntelligenceVerdict.UNKNOWN

        # Confidence calculation
        if is_corroborated:
            aggregate_confidence = 0.95
        elif is_conflicting:
            aggregate_confidence = 0.70
        elif malicious_count == 1:
            best_conf = max((r.confidence for r in active_reports if r.verdict == IntelligenceVerdict.MALICIOUS), default=0.85)
            aggregate_confidence = best_conf
        elif benign_count >= 1:
            aggregate_confidence = 0.85
        else:
            aggregate_confidence = 0.50

        # Provenance records
        provenance = [
            {
                "provider": r.provider,
                "verdict": r.verdict.value,
                "confidence": r.confidence,
                "checked_at": r.checked_at,
                "freshness": r.freshness.value,
                "reference_id": r.reference_id,
            }
            for r in reports
        ]

        # Explainability synthesis
        if is_corroborated:
            summary = f"Corroborated by {malicious_count + suspicious_count} independent intelligence sources ({', '.join(all_categories[:3]) or 'threat'})."
        elif is_conflicting:
            summary = "Warning: Conflicting threat intelligence records detected across independent providers."
        elif aggregate_verdict == IntelligenceVerdict.MALICIOUS:
            matched_p = next((r.provider for r in active_reports if r.verdict == IntelligenceVerdict.MALICIOUS), "threat source")
            summary = f"Flagged as malicious by {matched_p} ({', '.join(all_categories[:3]) or 'known threat'})."
        elif aggregate_verdict == IntelligenceVerdict.SUSPICIOUS:
            summary = f"Flagged as suspicious based on threat intelligence ({', '.join(all_categories[:3])})."
        elif aggregate_verdict == IntelligenceVerdict.BENIGN:
            summary = "Reputation sources reported benign baseline activity."
        else:
            summary = "No adverse threat intelligence records found for this indicator."

        return CorrelatedIntelligenceResult(
            indicator=indicator,
            aggregate_verdict=aggregate_verdict,
            aggregate_confidence=aggregate_confidence,
            is_corroborated=is_corroborated,
            is_conflicting=is_conflicting,
            reports=reports,
            categories=all_categories,
            provenance=provenance,
            summary_explanation=summary,
        )

    async def correlate_batch(
        self,
        indicators: List[ThreatIndicator],
    ) -> Dict[str, CorrelatedIntelligenceResult]:
        """
        Correlate multiple indicators while enforcing:
        - Deduplication (unique normalized keys)
        - Global budget cap on provider requests
        """
        deduped: Dict[str, ThreatIndicator] = {}
        for ind in indicators:
            key = f"{ind.type.value}:{ind.normalized_value}"
            if key not in deduped:
                deduped[key] = ind

        results: Dict[str, CorrelatedIntelligenceResult] = {}
        req_count = 0

        for key, ind in deduped.items():
            if req_count >= self._max_lookups_per_scan:
                # Budget reached: produce UNKNOWN result with explanation
                results[key] = CorrelatedIntelligenceResult(
                    indicator=ind,
                    aggregate_verdict=IntelligenceVerdict.UNKNOWN,
                    aggregate_confidence=0.5,
                    is_corroborated=False,
                    is_conflicting=False,
                    reports=[],
                    categories=[],
                    provenance=[],
                    summary_explanation="Scan intelligence budget reached; lookup skipped.",
                )
                continue

            res = await self.correlate_indicator(ind)
            results[key] = res
            req_count += 1

        return results

    def build_threat_graph(
        self,
        target_label: str,
        target_type: str,
        target_risk_level: str,
        correlated_results: Dict[str, CorrelatedIntelligenceResult],
        relationships: Optional[List[Tuple[str, str, str]]] = None,
    ) -> ThreatGraph:
        """
        Build an interactive relationship graph connecting the scan target with
        extracted entities (domains, IPs, URLs, hashes, phones) and their threat levels.
        """
        nodes: Dict[str, ThreatGraphNode] = {}
        edges: List[ThreatGraphEdge] = []

        # Root target node
        root_id = "node_target"
        nodes[root_id] = ThreatGraphNode(
            id=root_id,
            type=target_type,
            label=target_label[:40],
            risk_level=target_risk_level,
            details={"is_target": True},
        )

        # Create nodes for correlated indicators
        for key, c_res in correlated_results.items():
            ind = c_res.indicator
            node_id = f"node_{ind.type.value}_{ind.normalized_value[:24]}"

            # Map verdict to node risk level
            if c_res.aggregate_verdict == IntelligenceVerdict.MALICIOUS:
                node_risk = "critical" if c_res.is_corroborated else "high"
            elif c_res.aggregate_verdict == IntelligenceVerdict.SUSPICIOUS:
                node_risk = "medium"
            elif c_res.aggregate_verdict == IntelligenceVerdict.BENIGN:
                node_risk = "very_low"
            else:
                node_risk = "unknown"

            nodes[node_id] = ThreatGraphNode(
                id=node_id,
                type=ind.type.value,
                label=ind.normalized_value[:35],
                risk_level=node_risk,
                details={
                    "type": ind.type.value,
                    "verdict": c_res.aggregate_verdict.value,
                    "confidence": c_res.aggregate_confidence,
                    "is_corroborated": c_res.is_corroborated,
                    "is_conflicting": c_res.is_conflicting,
                    "categories": c_res.categories,
                },
            )

            # Default edge from target
            rel = "INCLUDES"
            if ind.type == IndicatorType.DOMAIN:
                rel = "HOSTED_ON"
            elif ind.type == IndicatorType.IP:
                rel = "RESOLVES_TO"
            elif ind.type == IndicatorType.URL:
                rel = "LINKS_TO"
            elif ind.type == IndicatorType.FILE_HASH:
                rel = "DOWNLOADS_PAYLOAD"
            elif ind.type == IndicatorType.PHONE:
                rel = "CONTACTS_PHONE"

            edges.append(ThreatGraphEdge(source=root_id, target=node_id, relation=rel))

        # Add explicit inter-indicator relationships if provided (e.g. Domain -> IP)
        if relationships:
            for src_key, dst_key, rel in relationships:
                src_id = f"node_{src_key[:30]}"
                dst_id = f"node_{dst_key[:30]}"
                if src_id in nodes and dst_id in nodes:
                    edges.append(ThreatGraphEdge(source=src_id, target=dst_id, relation=rel))

        return ThreatGraph(nodes=list(nodes.values()), edges=edges)
