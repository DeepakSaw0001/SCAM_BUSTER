"""
ScamBuster Scan Endpoints (v1)

Exposes interactive threat analysis endpoints:
- POST /api/v1/scan/url
- POST /api/v1/scan/text
- POST /api/v1/scan/email
- POST /api/v1/scan/phone
- POST /api/v1/scan/apk
- GET  /api/v1/scan/history
- GET  /api/v1/scan/{scan_id}
"""

from typing import List
from fastapi import APIRouter, HTTPException, Query, status

from app.schemas.scan import (
    ApkScanRequest,
    EmailScanRequest,
    PhoneScanRequest,
    ScanHistoryItem,
    ScanResultResponse,
    TextScanRequest,
    UrlScanRequest,
)
from app.services.analyzers import (
    analyze_apk,
    analyze_email,
    analyze_phone,
    analyze_text,
    analyze_url,
)
from app.ml.client import analyze_text_ml, analyze_url_ml
from app.risk_engine.engine import fuse_risk_analysis
from app.database.scan_repository import (
    get_recent_scans,
    get_scan_by_id,
    save_scan_result,
)

router = APIRouter(prefix="/scan", tags=["scans"])


@router.post("/url", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def scan_url_endpoint(request: UrlScanRequest) -> ScanResultResponse:
    """
    Execute Phase 02 URL detection pipeline:
    Validation -> Normalization -> Feature Extraction -> Rule Detection -> Risk Engine -> Explainable Result.
    Purely static/lexical analysis — no outbound requests (zero SSRF).
    """
    import uuid
    from datetime import datetime, timezone
    from app.services.url_validator import validate_url
    from app.services.url_normalizer import normalize_url
    from app.services.url_feature_extractor import extract_url_features
    from app.services.url_rule_detector import evaluate_url_rules
    from app.risk_engine.scorer import calculate_risk_score, MODEL_VERSION
    from app.risk_engine.categories import determine_categories
    from app.risk_engine.explanations import (
        generate_summary,
        generate_recommendation,
        generate_reasons,
    )
    from app.schemas.scan import ThreatIndicator

    # 1. Validation
    is_valid, validation_error = validate_url(request.url)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=validation_error or "Invalid URL input provided."
        )

    # 2. Normalization
    norm = normalize_url(request.url)

    # 3. Feature Extraction
    features = extract_url_features(request.url, norm)

    # 4. Rule-Based Detection
    findings = evaluate_url_rules(request.url, norm, features)

    # 5. Risk Engine
    risk_score, risk_level, confidence = calculate_risk_score(findings)
    categories = determine_categories(findings)
    summary = generate_summary(risk_level, findings, norm.normalized_url)
    recommendation = generate_recommendation(risk_level, findings)
    reasons = generate_reasons(findings)

    # 6. Format Threat Indicators
    indicators = [
        ThreatIndicator(
            name=f.name,
            severity=f.severity.upper(),
            description=f.description,
            evidence=f.evidence,
            rule_id=f.rule_id,
        )
        for f in findings
    ]

    scan_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    result = ScanResultResponse(
        id=scan_id,
        scan_id=scan_id,
        scan_type="url",
        input_type="url",
        status="completed",
        target=norm.original_url,
        timestamp=now,
        created_at=now,
        composite_risk_score=risk_score,
        risk_score=risk_score,
        risk_level=risk_level.upper(),
        category=categories,
        confidence=confidence,
        summary=summary,
        heuristic_score=risk_score,
        indicators=indicators,
        recommendation=recommendation,
        recommendations=[recommendation],
        reasons=reasons,
        model_version=MODEL_VERSION,
        normalized_url=norm.normalized_url,
        features=features.model_dump(),
        technical_details={
            "hostname": norm.hostname,
            "port": norm.port,
            "scheme": norm.scheme,
            "is_ip": norm.is_ip,
            "features": features.model_dump(),
        },
    )

    await save_scan_result(result)
    return result


@router.post("/text", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def scan_text_endpoint(request: TextScanRequest) -> ScanResultResponse:
    """Analyze SMS or text messages for social engineering, lures, and NLP spam signals."""
    heuristic_res = analyze_text(request.text, sender=request.sender)
    ml_res = analyze_text_ml(request.text)
    fused = fuse_risk_analysis("text", request.text[:100], heuristic_res, ml_res)
    await save_scan_result(fused)
    return fused


@router.post("/email", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def scan_email_endpoint(request: EmailScanRequest) -> ScanResultResponse:
    """Analyze email headers, sender domain, attachment risks, and body content."""
    heuristic_res = analyze_email(
        sender=request.sender,
        subject=request.subject,
        body=request.body,
        reply_to=request.reply_to,
        attachments=request.attachments,
    )
    # Feed email body to text ML classifier
    ml_res = analyze_text_ml(f"{request.subject} {request.body}")
    target_desc = f"Email from {request.sender}: '{request.subject[:60]}'"
    fused = fuse_risk_analysis("email", target_desc, heuristic_res, ml_res)
    await save_scan_result(fused)
    return fused


@router.post("/phone", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def scan_phone_endpoint(request: PhoneScanRequest) -> ScanResultResponse:
    """Analyze phone numbers for toll fraud (Wangiri), spoofing, and impersonation context."""
    heuristic_res = analyze_phone(request.phone_number, context=request.context)
    fused = fuse_risk_analysis("phone", request.phone_number, heuristic_res, ml_result=None)
    await save_scan_result(fused)
    return fused


@router.post("/apk", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def scan_apk_endpoint(request: ApkScanRequest) -> ScanResultResponse:
    """Analyze Android APK permissions and package metadata for banking trojan & spyware signatures."""
    heuristic_res = analyze_apk(
        package_name=request.package_name,
        permissions=request.permissions,
        app_name=request.app_name,
    )
    target_desc = request.app_name or request.package_name
    fused = fuse_risk_analysis("apk", target_desc, heuristic_res, ml_result=None)
    await save_scan_result(fused)
    return fused


@router.get("/history", response_model=List[ScanHistoryItem], status_code=status.HTTP_200_OK)
async def scan_history_endpoint(limit: int = Query(50, ge=1, le=100)) -> List[ScanHistoryItem]:
    """Retrieve recent scan history across all channels."""
    return await get_recent_scans(limit=limit)


@router.get("/{scan_id}", response_model=ScanResultResponse, status_code=status.HTTP_200_OK)
async def get_scan_endpoint(scan_id: str) -> ScanResultResponse:
    """Retrieve full details of a specific scan by ID."""
    scan = await get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan result with ID '{scan_id}' not found.",
        )
    return scan
