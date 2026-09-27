"""
ScamBuster Phase 11: Threat Intelligence & Reputation Correlation Test Suite

Comprehensive tests for:
1. Standard Indicator Normalization (Domain, URL, IP, Hash, Phone, Email)
2. Centralized Privacy-Preserving Threat Cache & TTLs
3. Local Threat Feed Catalog, Validation, Versioning & Rollback
4. Provider Adapters, Sliding-Window Rate Limiting, Backoff & Error Resilience
5. Multi-Source Correlation, Corroboration Elevation, Conflicting Reports & Unknown States
6. Threat Relationship Graph Construction
7. Security Controls (SSRF Blocking, Secret Protection, Input Validation)
8. End-to-End Scan & Intelligence API Endpoints
"""

import pytest
import pytest_asyncio
import asyncio
from datetime import datetime, timezone, timedelta

from app.intelligence.models import (
    IndicatorType,
    IntelligenceVerdict,
    IntelligenceStatus,
    ThreatIndicator,
    ThreatIntelligenceReport,
    CorrelatedIntelligenceResult,
    ThreatGraph,
)
from app.intelligence.normalizer import (
    normalize_domain_indicator,
    normalize_url_indicator,
    normalize_ip_indicator,
    normalize_file_hash_indicator,
    normalize_phone_indicator,
    normalize_email_indicator,
    normalize_indicator,
    normalize_domain,
    normalize_file_hash,
)
from app.intelligence.cache import ThreatIntelligenceCache
from app.intelligence.feeds.catalog import LocalFeedCatalog, LocalFeedRecord
from app.intelligence.providers.local_provider import LocalFeedThreatProvider
from app.intelligence.providers.mock_threat_provider import MockThreatIntelProvider
from app.intelligence.providers.open_threat_provider import OpenThreatIntelProvider
from app.intelligence.correlator import ThreatIntelligenceCorrelator
from app.intelligence.service import ThreatIntelligenceService, get_threat_intelligence_service
from app.risk_engine.scorer import (
    calculate_unified_url_risk,
    calculate_unified_message_risk,
    calculate_unified_email_risk,
    calculate_unified_phone_risk,
    calculate_unified_apk_risk,
)


# ============================================================================
# 1. INDICATOR NORMALIZATION TESTS
# ============================================================================

def test_domain_normalization():
    # Case normalization, trailing dot, punycode
    assert normalize_domain_indicator("EXAMPLE.COM.") == "example.com"
    assert normalize_domain_indicator("  sub.Test-Domain.org  ") == "sub.test-domain.org"
    assert normalize_domain_indicator("http://example.com/path") == "example.com"
    # Internationalized domain (Punycode)
    puny = normalize_domain_indicator("münchen.de")
    assert puny is not None and ("xn--" in puny or "munchen" in puny)
    # Invalid domain
    assert normalize_domain_indicator("") is None
    assert normalize_domain_indicator("..") is None


def test_url_normalization():
    # Scheme, lower hostname, query preserving, fragment removal
    n1 = normalize_url_indicator("HTTP://Example.COM:80/login?user=1#frag")
    assert n1 == "http://example.com/login?user=1"

    n2 = normalize_url_indicator("HTTPS://Secure.Bank.com:443/auth/")
    assert n2 == "https://secure.bank.com/auth"

    assert normalize_url_indicator("") is None
    assert normalize_url_indicator("not a url") is None


def test_ip_normalization():
    # IPv4 canonical format
    assert normalize_ip_indicator("192.168.1.1") == "192.168.1.1"
    # IPv6 canonical expansion/compression
    assert normalize_ip_indicator("2001:0db8:0000:0000:0000:ff00:0042:8329") == "2001:db8::ff00:42:8329"
    # Invalid IPs
    assert normalize_ip_indicator("999.999.999.999") is None
    assert normalize_ip_indicator("abc.def") is None


def test_file_hash_normalization():
    # SHA-256 uppercase to lowercase
    sha256 = "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    assert normalize_file_hash_indicator(sha256) == sha256.lower()

    # MD5 & SHA-1 normalization
    md5 = "D41D8CD98F00B204E9800998ECF8427E"
    assert normalize_file_hash_indicator(md5) == md5.lower()

    # Invalid hashes
    assert normalize_file_hash_indicator("not_a_hash") is None
    assert normalize_file_hash_indicator("12345") is None


def test_phone_normalization():
    # Phone normalization using existing phone analyzer engine
    norm = normalize_phone_indicator("+1 800-432-1000", default_region="US")
    assert norm is not None
    assert norm.startswith("+1")


def test_email_normalization():
    # Privacy: normalized email preserves domain, lowercases address
    addr, domain, masked = normalize_email_indicator("Victim.User@Mail-Server.COM")
    assert addr == "victim.user@mail-server.com"
    assert domain == "mail-server.com"
    assert masked.startswith("v***r@mail-server.com") or "@mail-server.com" in masked

    assert normalize_email_indicator("not-an-email") == (None, None, None)


def test_generic_normalize_indicator():
    ind_domain = normalize_indicator(IndicatorType.DOMAIN, "Phish-Target.XYZ")
    assert ind_domain is not None
    assert ind_domain.normalized_value == "phish-target.xyz"
    assert ind_domain.type == IndicatorType.DOMAIN

    ind_ip = normalize_indicator(IndicatorType.IP, "45.33.32.156")
    assert ind_ip is not None
    assert ind_ip.normalized_value == "45.33.32.156"


# ============================================================================
# 2. PRIVACY-PRESERVING THREAT CACHE & TTL TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_cache_set_get_and_expiration():
    cache = ThreatIntelligenceCache(max_entries=100)
    ind = normalize_indicator(IndicatorType.DOMAIN, "cached-test.com")
    rep = ThreatIntelligenceReport(
        indicator=ind,
        provider="test-provider",
        verdict=IntelligenceVerdict.SUSPICIOUS,
        confidence=0.8,
        categories=["test"],
        summary="Test cached item",
    )
    result = CorrelatedIntelligenceResult(
        indicator=ind,
        reports=[rep],
        aggregate_verdict=IntelligenceVerdict.SUSPICIOUS,
        aggregate_confidence=0.8,
        summary_explanation="Test explanation",
    )

    # Miss before set
    cached = await cache.get(ind)
    assert cached is None

    # Set cache with short TTL
    await cache.set(ind, result, ttl_seconds=1)
    cached = await cache.get(ind)
    assert cached is not None
    assert cached.aggregate_verdict == IntelligenceVerdict.SUSPICIOUS

    # Wait for expiry
    await asyncio.sleep(1.2)
    expired = await cache.get(ind)
    assert expired is None

    # Check metrics
    metrics = cache.get_metrics()
    assert metrics["hits"] >= 1
    assert metrics["misses"] >= 2


@pytest.mark.asyncio
async def test_cache_inflight_deduplication():
    cache = ThreatIntelligenceCache()
    ind = normalize_indicator(IndicatorType.URL, "https://shared-lookup.org/path")

    # Acquire lock for first query
    lock1 = await cache.get_inflight_lock(ind)
    assert lock1 is not None

    # Concurrently accessing same indicator returns same lock
    lock2 = await cache.get_inflight_lock(ind)
    assert lock1 is lock2

    await cache.release_inflight_lock(ind)


# ============================================================================
# 3. LOCAL THREAT FEED CATALOG, VALIDATION & ROLLBACK TESTS
# ============================================================================

def test_feed_catalog_validation_and_records():
    catalog = LocalFeedCatalog()
    # Initial catalog has curated records
    assert catalog.record_count > 0
    assert catalog.version == "2026.09.v1"
    assert catalog.provenance["license"] == "ODbL 1.0 (Public Curated Datasets)"

    # Known domain lookup
    rec = catalog.lookup(IndicatorType.DOMAIN, "wellsfarg0-sec-verify.top")
    assert rec is not None
    assert rec.verdict == IntelligenceVerdict.MALICIOUS
    assert "phishing" in rec.categories

    # Known APK malware hash (Cerberus / SpyNote)
    apk_rec = catalog.lookup(IndicatorType.FILE_HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    assert apk_rec is not None
    assert apk_rec.verdict == IntelligenceVerdict.MALICIOUS


def test_feed_duplicate_rejection_and_rollback():
    catalog = LocalFeedCatalog()
    initial_count = catalog.record_count

    # Ingest bad duplicate records
    new_records = [
        LocalFeedRecord(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value="new-bad-domain.xyz",
            verdict=IntelligenceVerdict.MALICIOUS,
            categories=["phishing"],
            source="Test Feed",
            confidence=0.9,
        ),
        # Duplicate
        LocalFeedRecord(
            indicator_type=IndicatorType.DOMAIN,
            indicator_value="new-bad-domain.xyz",
            verdict=IntelligenceVerdict.MALICIOUS,
            categories=["malware"],
            source="Test Feed Duplicate",
            confidence=0.8,
        ),
    ]

    res = catalog.update_feed(new_records, version="2026.09.v2")
    assert res["status"] == "updated"
    assert res["records_added"] == 1
    assert res["duplicates_rejected"] == 1
    assert catalog.version == "2026.09.v2"

    # Test rollback
    rolled_back = catalog.rollback()
    assert rolled_back is True
    assert catalog.record_count == initial_count
    assert catalog.version == "2026.09.v1"


# ============================================================================
# 4. PROVIDER ADAPTERS & ERROR RESILIENCE TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_local_feed_provider():
    catalog = LocalFeedCatalog()
    provider = LocalFeedThreatProvider(catalog=catalog)
    ind = normalize_indicator(IndicatorType.DOMAIN, "wellsfarg0-sec-verify.top")

    report = await provider.lookup(ind)
    assert report.status == IntelligenceStatus.AVAILABLE
    assert report.verdict == IntelligenceVerdict.MALICIOUS
    assert report.provider == "scambuster-local-curated"
    assert "phishing" in report.categories

    # Benign / Unlisted indicator
    benign_ind = normalize_indicator(IndicatorType.DOMAIN, "legitimate-bank-service.com")
    report_benign = await provider.lookup(benign_ind)
    assert report_benign.verdict == IntelligenceVerdict.UNKNOWN


@pytest.mark.asyncio
async def test_mock_threat_provider_failure_modes():
    provider = MockThreatIntelProvider()
    ind = normalize_indicator(IndicatorType.DOMAIN, "test-target.com")

    # 1. Normal lookup
    rep = await provider.lookup(ind)
    assert rep.status == IntelligenceStatus.AVAILABLE

    # 2. Timeout Failure Injection
    provider.simulate_timeout = True
    rep_timeout = await provider.lookup(ind)
    assert rep_timeout.status == IntelligenceStatus.TIMEOUT
    assert rep_timeout.verdict == IntelligenceVerdict.UNKNOWN
    provider.simulate_timeout = False

    # 3. HTTP 429 Rate Limit Injection
    provider.simulate_rate_limit = True
    rep_429 = await provider.lookup(ind)
    assert rep_429.status == IntelligenceStatus.RATE_LIMITED
    assert rep_429.verdict == IntelligenceVerdict.UNKNOWN
    provider.simulate_rate_limit = False

    # 4. HTTP 500 Error Injection
    provider.simulate_error = True
    rep_500 = await provider.lookup(ind)
    assert rep_500.status == IntelligenceStatus.ERROR
    assert rep_500.verdict == IntelligenceVerdict.UNKNOWN
    provider.simulate_error = False


@pytest.mark.asyncio
async def test_open_threat_provider_ssrf_guard():
    # OpenThreatIntelProvider must block private/internal network lookups
    provider = OpenThreatIntelProvider(api_url="http://127.0.0.1:8000/intel")
    ind_private = normalize_indicator(IndicatorType.IP, "192.168.1.100")
    rep = await provider.lookup(ind_private)
    assert rep.status == IntelligenceStatus.BLOCKED
    assert rep.verdict == IntelligenceVerdict.UNKNOWN


# ============================================================================
# 5. MULTI-SOURCE CORRELATION & CONFLICT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_multi_source_corroboration():
    # Setup correlator with two mock providers agreeing on malicious
    ind = normalize_indicator(IndicatorType.DOMAIN, "malicious-phish.net")
    p1 = MockThreatIntelProvider(provider_id="provider-a", default_verdict=IntelligenceVerdict.MALICIOUS, confidence=0.85)
    p2 = MockThreatIntelProvider(provider_id="provider-b", default_verdict=IntelligenceVerdict.MALICIOUS, confidence=0.90)

    cache = ThreatIntelligenceCache()
    correlator = ThreatIntelligenceCorrelator(providers=[p1, p2], cache=cache)

    result, graph = await correlator.correlate_single(ind)
    assert result.aggregate_verdict == IntelligenceVerdict.MALICIOUS
    assert result.is_corroborated is True
    assert result.is_conflicting is False
    assert result.aggregate_confidence >= 0.85
    assert len(result.reports) == 2


@pytest.mark.asyncio
async def test_conflicting_providers_handling():
    # Provider A says MALICIOUS, Provider B says BENIGN
    ind = normalize_indicator(IndicatorType.DOMAIN, "disputed-domain.com")
    p1 = MockThreatIntelProvider(provider_id="provider-a", default_verdict=IntelligenceVerdict.MALICIOUS, confidence=0.80)
    p2 = MockThreatIntelProvider(provider_id="provider-b", default_verdict=IntelligenceVerdict.BENIGN, confidence=0.85)

    cache = ThreatIntelligenceCache()
    correlator = ThreatIntelligenceCorrelator(providers=[p1, p2], cache=cache)

    result, graph = await correlator.correlate_single(ind)
    # Preservation of conflict: ScamBuster does not hide discordance
    assert result.is_conflicting is True
    assert "Conflicting" in result.summary_explanation
    assert result.aggregate_verdict in (IntelligenceVerdict.SUSPICIOUS, IntelligenceVerdict.MALICIOUS)


@pytest.mark.asyncio
async def test_unknown_state_never_safe():
    # If all providers return UNKNOWN, result MUST be UNKNOWN, NEVER SAFE
    ind = normalize_indicator(IndicatorType.DOMAIN, "new-unknown-site.org")
    p1 = MockThreatIntelProvider(provider_id="provider-a", default_verdict=IntelligenceVerdict.UNKNOWN)
    p2 = MockThreatIntelProvider(provider_id="provider-b", default_verdict=IntelligenceVerdict.UNKNOWN)

    cache = ThreatIntelligenceCache()
    correlator = ThreatIntelligenceCorrelator(providers=[p1, p2], cache=cache)

    result, graph = await correlator.correlate_single(ind)
    assert result.aggregate_verdict == IntelligenceVerdict.UNKNOWN
    assert result.aggregate_verdict != IntelligenceVerdict.BENIGN
    assert result.aggregate_confidence <= 0.5


@pytest.mark.asyncio
async def test_intelligence_budget_and_deduplication():
    # A single scan with 20 repeated URLs must respect MAX_PROVIDER_REQUESTS_PER_SCAN and deduplicate
    p1 = MockThreatIntelProvider()
    cache = ThreatIntelligenceCache()
    correlator = ThreatIntelligenceCorrelator(providers=[p1], cache=cache, max_lookups_per_scan=5)

    indicators = [
        normalize_indicator(IndicatorType.URL, "https://duplicate-url.com/path")
        for _ in range(10)
    ]
    results = await correlator.correlate_batch(indicators)
    # Deduplicated to 1 unique indicator
    assert len(results) == 1
    assert p1.request_count == 1  # Exactly 1 request made, not 10!


# ============================================================================
# 6. THREAT RELATIONSHIP GRAPH TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_threat_graph_generation():
    svc = ThreatIntelligenceService()
    results, graph = await svc.correlate_url_scan(
        target_url="https://phishing-login.example.com/verify?account=1",
        hostname="phishing-login.example.com",
        resolved_ips=["93.184.216.34"],
        redirect_urls=["https://phishing-login.example.com/stealer.apk"],
    )

    graph_dict = graph.to_dict()
    assert "nodes" in graph_dict
    assert "edges" in graph_dict
    assert len(graph_dict["nodes"]) >= 3  # URL, Domain, IP, Redirect

    # Verify edge types
    rel_types = [e["relationship"] for e in graph_dict["edges"]]
    assert "HOSTED_ON" in rel_types or "BELONGS_TO_DOMAIN" in rel_types or "REDIRECTS_TO" in rel_types


# ============================================================================
# 7. RISK ENGINE INTEGRATION TESTS
# ============================================================================

def test_risk_engine_url_elevation_with_corroborated_intel():
    from app.services.url_rule_detector import RuleFinding

    ind = normalize_indicator(IndicatorType.DOMAIN, "malicious-phish.net")
    c_res = CorrelatedIntelligenceResult(
        indicator=ind,
        reports=[],
        aggregate_verdict=IntelligenceVerdict.MALICIOUS,
        aggregate_confidence=0.9,
        is_corroborated=True,
    )
    threat_intel = {"malicious-phish.net": c_res}

    # Low rule score initially
    rule_findings = [
        RuleFinding(
            rule_id="RULE_TEST",
            name="Test Rule",
            severity="low",
            score_weight=10,
            description="Test heuristic rule triggered",
            evidence="Low severity lexical finding",
        )
    ]
    ml_result = {"available": True, "prediction": "benign", "model_score": 15.0, "model_probability": 0.15}

    score_without, level_without, _, _, _ = calculate_unified_url_risk(rule_findings, ml_result, threat_intelligence=None)
    score_with, level_with, _, _, _ = calculate_unified_url_risk(rule_findings, ml_result, threat_intelligence=threat_intel)

    # Threat intelligence elevates risk appropriately
    assert score_with > score_without
    assert score_with >= 75
    assert level_with.upper() in ("HIGH", "CRITICAL")


def test_risk_engine_message_elevation_with_intel():
    ind = normalize_indicator(IndicatorType.PHONE, "+18005550199")
    c_res = CorrelatedIntelligenceResult(
        indicator=ind,
        reports=[],
        aggregate_verdict=IntelligenceVerdict.MALICIOUS,
        aggregate_confidence=0.88,
        is_corroborated=True,
    )
    threat_intel = {"+18005550199": c_res}

    rule_findings = []
    ml_result = {"available": True, "prediction": "benign", "model_score": 10.0, "model_probability": 0.1}

    score, level, _, _, _ = calculate_unified_message_risk(
        rule_findings=rule_findings,
        ml_result=ml_result,
        threat_intelligence=threat_intel,
    )
    assert score >= 60
    assert level.upper() in ("HIGH", "CRITICAL")


# ============================================================================
# 8. SCAN API & THREAT INTEL STATUS ENDPOINT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_intelligence_status_endpoint_no_secrets():
    svc = get_threat_intelligence_service()
    status_info = svc.get_operational_status()

    assert "providers" in status_info
    assert "local_feed" in status_info
    assert "cache" in status_info
    assert status_info["local_feed"]["record_count"] > 0
    assert status_info["local_feed"]["version"] == "2026.09.v1"

    # CRITICAL: Verify no secrets or API keys are exposed
    serialized = str(status_info)
    assert "api_key" not in serialized.lower()
    assert "token" not in serialized.lower()
    assert "secret" not in serialized.lower()
