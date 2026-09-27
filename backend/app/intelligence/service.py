"""
ScamBuster — Central Threat Intelligence Service (Phase 11)

Singleton service unifying threat intelligence correlation across all scan modalities:
- URL scans (domain, IP, redirect hops, payload hash)
- Message scans (embedded URLs, phone numbers, sender)
- Email scans (sender domain, reply-to, attachments, links, phones)
- APK scans (package SHA-256, embedded C2 domains)
- Phone scans (normalized phone numbers)
"""

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from app.intelligence.cache import IntelligenceCache
from app.intelligence.correlator import ThreatIntelligenceCorrelator
from app.intelligence.models import (
    CorrelatedIntelligenceResult,
    IndicatorType,
    ThreatGraph,
    ThreatIndicator,
)
from app.intelligence.normalizer import normalize_indicator
from app.intelligence.providers.base import BaseThreatIntelProvider
from app.intelligence.providers.local_provider import LocalFeedThreatProvider
from app.intelligence.providers.mock_threat_provider import MockThreatIntelProvider
from app.intelligence.providers.open_threat_provider import OpenThreatIntelProvider

logger = logging.getLogger("scambuster.intelligence.service")


class ThreatIntelligenceService:
    """
    Central orchestration service for threat intelligence lookups, caching,
    correlation, and graph synthesis across ScamBuster.
    """

    def __init__(
        self,
        providers: Optional[List[BaseThreatIntelProvider]] = None,
        cache: Optional[IntelligenceCache] = None,
    ):
        self._cache = cache or IntelligenceCache()
        if providers is None:
            self._providers = self._init_default_providers()
        else:
            self._providers = providers

        self._correlator = ThreatIntelligenceCorrelator(
            providers=self._providers,
            cache=self._cache,
        )

    def _init_default_providers(self) -> List[BaseThreatIntelProvider]:
        provs: List[BaseThreatIntelProvider] = [LocalFeedThreatProvider()]

        # Check for Open Threat API configuration
        open_prov = OpenThreatIntelProvider()
        if open_prov.is_configured():
            provs.append(open_prov)
            logger.info("Open threat intelligence provider enabled.")

        # Check for Mock provider in development/test
        if os.getenv("MOCK_INTEL_ENABLED", "false").lower() == "true":
            provs.append(MockThreatIntelProvider(name="mock-provider", configured=True))
            logger.info("Mock threat intelligence provider registered.")

        return provs

    @property
    def correlator(self) -> ThreatIntelligenceCorrelator:
        return self._correlator

    @property
    def cache(self) -> IntelligenceCache:
        return self._cache

    def set_providers(self, providers: List[BaseThreatIntelProvider]) -> None:
        self._providers = providers
        self._correlator.set_providers(providers)

    async def correlate_url_scan(
        self,
        target_url: Optional[str] = None,
        url: Optional[str] = None,
        domain: Optional[str] = None,
        hostname: Optional[str] = None,
        resolved_ips: Optional[List[str]] = None,
        redirect_urls: Optional[List[str]] = None,
        download_hashes: Optional[List[str]] = None,
        target_risk_level: str = "unknown",
        **kwargs: Any,
    ) -> Tuple[Dict[str, CorrelatedIntelligenceResult], ThreatGraph]:
        """Correlate all indicators extracted during a URL / Web scan."""
        effective_url = target_url or url or ""
        effective_domain = domain or hostname
        indicators: List[ThreatIndicator] = []

        # Target URL
        if effective_url:
            try:
                indicators.append(normalize_indicator(IndicatorType.URL, effective_url, source="target_url"))
            except Exception:
                pass

        # Target Domain
        if effective_domain:
            try:
                indicators.append(normalize_indicator(IndicatorType.DOMAIN, effective_domain, source="target_domain"))
            except Exception:
                pass

        # Resolved IPs
        for ip in (resolved_ips or [])[:3]:
            try:
                indicators.append(normalize_indicator(IndicatorType.IP, ip, source="dns_resolution"))
            except Exception:
                pass

        # Redirect Destinations
        for r_url in (redirect_urls or [])[:3]:
            try:
                indicators.append(normalize_indicator(IndicatorType.URL, r_url, source="redirect_hop"))
            except Exception:
                pass

        # Downloaded payload hashes
        for h in (download_hashes or [])[:2]:
            try:
                indicators.append(normalize_indicator(IndicatorType.FILE_HASH, h, source="download_payload"))
            except Exception:
                pass

        results = await self._correlator.correlate_batch(indicators)
        graph = self._correlator.build_threat_graph(
            target_label=target_url,
            target_type="url",
            target_risk_level=target_risk_level,
            correlated_results=results,
        )
        return results, graph

    async def correlate_message_scan(
        self,
        message_text: str,
        extracted_urls: Optional[List[str]] = None,
        extracted_phones: Optional[List[str]] = None,
        sender: Optional[str] = None,
        target_risk_level: str = "unknown",
    ) -> Tuple[Dict[str, CorrelatedIntelligenceResult], ThreatGraph]:
        """Correlate all indicators extracted from SMS or chat text."""
        indicators: List[ThreatIndicator] = []

        for u in (extracted_urls or [])[:5]:
            try:
                ind = normalize_indicator(IndicatorType.URL, u, source="embedded_link")
                indicators.append(ind)
                # Also include domain
                host = ind.metadata.get("hostname")
                if host:
                    indicators.append(normalize_indicator(IndicatorType.DOMAIN, host, source="embedded_domain"))
            except Exception:
                pass

        for p in (extracted_phones or [])[:3]:
            try:
                indicators.append(normalize_indicator(IndicatorType.PHONE, p, source="embedded_phone"))
            except Exception:
                pass

        if sender and (sender.startswith("+") or sender.isdigit()):
            try:
                indicators.append(normalize_indicator(IndicatorType.PHONE, sender, source="sender_phone"))
            except Exception:
                pass

        results = await self._correlator.correlate_batch(indicators)
        label = (message_text[:35] + "...") if len(message_text) > 35 else message_text
        graph = self._correlator.build_threat_graph(
            target_label=label or "Message Scan",
            target_type="message",
            target_risk_level=target_risk_level,
            correlated_results=results,
        )
        return results, graph

    async def correlate_email_scan(
        self,
        subject: Optional[str] = None,
        sender_email: Optional[str] = None,
        sender_domain: Optional[str] = None,
        reply_to_email: Optional[str] = None,
        reply_to_domain: Optional[str] = None,
        extracted_urls: Optional[List[str]] = None,
        attachment_hashes: Optional[List[str]] = None,
        extracted_phones: Optional[List[str]] = None,
        target_risk_level: str = "unknown",
        **kwargs: Any,
    ) -> Tuple[Dict[str, CorrelatedIntelligenceResult], ThreatGraph]:
        """Correlate all indicators extracted from an email."""
        indicators: List[ThreatIndicator] = []

        # If sender_domain not provided directly, infer from sender_email
        if not sender_domain and sender_email and "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].strip()

        if sender_domain:
            try:
                indicators.append(normalize_indicator(IndicatorType.DOMAIN, sender_domain, source="sender_domain"))
            except Exception:
                pass

        if not reply_to_domain and reply_to_email and "@" in reply_to_email:
            reply_to_domain = reply_to_email.split("@")[-1].strip()

        if reply_to_domain and reply_to_domain != sender_domain:
            try:
                indicators.append(normalize_indicator(IndicatorType.DOMAIN, reply_to_domain, source="reply_to_domain"))
            except Exception:
                pass

        for u in (extracted_urls or [])[:5]:
            try:
                ind = normalize_indicator(IndicatorType.URL, u, source="email_link")
                indicators.append(ind)
                host = ind.metadata.get("hostname")
                if host:
                    indicators.append(normalize_indicator(IndicatorType.DOMAIN, host, source="link_domain"))
            except Exception:
                pass

        for h in (attachment_hashes or [])[:4]:
            try:
                indicators.append(normalize_indicator(IndicatorType.FILE_HASH, h, source="attachment_hash"))
            except Exception:
                pass

        for p in (extracted_phones or [])[:3]:
            try:
                indicators.append(normalize_indicator(IndicatorType.PHONE, p, source="body_phone"))
            except Exception:
                pass

        results = await self._correlator.correlate_batch(indicators)
        label_subj = subject[:30] if subject else (sender_domain or "Email Scan")
        graph = self._correlator.build_threat_graph(
            target_label=f"Email: {label_subj}",
            target_type="email",
            target_risk_level=target_risk_level,
            correlated_results=results,
        )
        return results, graph

    async def correlate_apk_scan(
        self,
        sha256_hash: str,
        package_name: str,
        app_name: Optional[str] = None,
        embedded_urls: Optional[List[str]] = None,
        c2_domains: Optional[List[str]] = None,
        target_risk_level: str = "unknown",
        **kwargs: Any,
    ) -> Tuple[Dict[str, CorrelatedIntelligenceResult], ThreatGraph]:
        """Correlate APK package hash and extracted C2 network destinations."""
        indicators: List[ThreatIndicator] = []

        try:
            indicators.append(normalize_indicator(IndicatorType.FILE_HASH, sha256_hash, source="apk_sha256"))
        except Exception:
            pass

        # Handle explicit c2 domains
        domains_to_check = list(c2_domains or [])
        # Also extract domains from embedded URLs
        for eu in (embedded_urls or [])[:5]:
            try:
                ind = normalize_indicator(IndicatorType.URL, eu, source="apk_embedded_url")
                indicators.append(ind)
                host = ind.metadata.get("hostname")
                if host and host not in domains_to_check:
                    domains_to_check.append(host)
            except Exception:
                pass

        for dom in domains_to_check[:4]:
            try:
                indicators.append(normalize_indicator(IndicatorType.DOMAIN, dom, source="apk_embedded_c2"))
            except Exception:
                pass

        results = await self._correlator.correlate_batch(indicators)
        display_label = app_name or package_name or "APK Scan"
        graph = self._correlator.build_threat_graph(
            target_label=display_label[:35],
            target_type="apk",
            target_risk_level=target_risk_level,
            correlated_results=results,
        )
        return results, graph

    async def correlate_phone_scan(
        self,
        phone_number: str,
        region: Optional[str] = None,
        target_risk_level: str = "unknown",
        **kwargs: Any,
    ) -> Tuple[Dict[str, CorrelatedIntelligenceResult], ThreatGraph]:
        """Correlate phone number against known scam registries."""
        indicators: List[ThreatIndicator] = []
        try:
            extra = {"region": region} if region else {}
            indicators.append(normalize_indicator(IndicatorType.PHONE, phone_number, source="target_phone", extra_metadata=extra))
        except Exception:
            pass

        results = await self._correlator.correlate_batch(indicators)
        graph = self._correlator.build_threat_graph(
            target_label=phone_number,
            target_type="phone",
            target_risk_level=target_risk_level,
            correlated_results=results,
        )
        return results, graph

    def get_metrics(self) -> Dict[str, Any]:
        """Return operational telemetry metrics."""
        return {
            "cache": self._cache.get_metrics(),
            "providers_count": len(self._providers),
            "providers": [
                {
                    "name": p.name,
                    "is_configured": p.is_configured(),
                    "supported_types": [t.value for t in p.supported_indicator_types],
                }
                for p in self._providers
            ],
        }

    def get_operational_status(self) -> Dict[str, Any]:
        """Return operational status and metadata without exposing secrets."""
        from app.intelligence.feeds.catalog import LocalFeedCatalog
        catalog = LocalFeedCatalog()
        return {
            "status": "operational",
            "cache": self._cache.get_metrics(),
            "providers_count": len(self._providers),
            "providers": [
                {
                    "name": p.name,
                    "is_configured": p.is_configured(),
                    "supported_types": [t.value for t in p.supported_indicator_types],
                }
                for p in self._providers
            ],
            "local_feed": {
                "version": catalog.version,
                "record_count": catalog.record_count,
                "license": catalog.provenance.get("license"),
                "source": catalog.provenance.get("source"),
            },
        }

    async def correlate_single(
        self,
        value: str,
        indicator_type: Optional[IndicatorType] = None,
    ) -> Optional[CorrelatedIntelligenceResult]:
        """Correlate a single indicator value."""
        if indicator_type is None:
            from app.intelligence.normalizer import detect_indicator_type
            indicator_type = detect_indicator_type(value)
        try:
            ind = normalize_indicator(indicator_type, value, source="manual_lookup")
        except Exception:
            return None
        return await self._correlator.correlate_indicator(ind)


# Global singleton instance
_threat_intel_service_instance = ThreatIntelligenceService()


def get_threat_intelligence_service() -> ThreatIntelligenceService:
    """Return singleton instance of ThreatIntelligenceService."""
    return _threat_intel_service_instance
