from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


# --- Request Schemas ---

class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to analyze")


class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=2, max_length=10000, description="SMS or message text to analyze")
    sender: Optional[str] = Field(None, max_length=128, description="Optional sender info or phone number")


class EmailScanRequest(BaseModel):
    subject: str = Field("", max_length=512, description="Email subject line")
    sender: str = Field(..., min_length=3, max_length=256, description="From email address / display name")
    body: str = Field(..., min_length=1, max_length=50000, description="Email body content")
    reply_to: Optional[str] = Field(None, max_length=256, description="Reply-To header")
    attachments: Optional[List[str]] = Field(default_factory=list, description="List of attachment filenames")


class PhoneScanRequest(BaseModel):
    phone_number: str = Field(..., min_length=3, max_length=32, description="Phone number to check")
    context: Optional[str] = Field(None, max_length=512, description="Optional caller context or claimed organization")


class ApkScanRequest(BaseModel):
    package_name: str = Field(..., min_length=3, max_length=256, description="App package name e.g. com.example.app")
    app_name: Optional[str] = Field(None, max_length=128, description="Human readable application name")
    permissions: List[str] = Field(..., min_length=1, description="List of Android permissions requested by APK")


# --- Response Schemas ---

class ThreatIndicator(BaseModel):
    name: str
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    description: str
    evidence: Optional[str] = None


class MLMetadata(BaseModel):
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    prediction: Optional[str] = None
    probability: Optional[float] = None
    target_probability: Optional[float] = None
    features_used: Optional[int] = None
    details: Optional[Dict[str, Any]] = None


class ScanResultResponse(BaseModel):
    id: str
    scan_type: Literal["url", "text", "email", "phone", "apk"]
    target: str
    timestamp: datetime
    composite_risk_score: int = Field(..., ge=0, le=100, description="Risk score from 0 (clean) to 100 (critical)")
    risk_level: Literal["SAFE", "SUSPICIOUS", "DANGEROUS"]
    summary: str
    heuristic_score: int
    indicators: List[ThreatIndicator]
    recommendations: List[str]
    ml_metadata: Optional[MLMetadata] = None
    technical_details: Optional[Dict[str, Any]] = None


class ScanHistoryItem(BaseModel):
    id: str
    scan_type: str
    target: str
    timestamp: datetime
    composite_risk_score: int
    risk_level: str
    summary: str
