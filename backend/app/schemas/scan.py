from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field, model_validator


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
    severity: str = Field(..., description="critical, high, medium, low, or info")
    description: str
    evidence: Optional[str] = None
    rule_id: Optional[str] = None


class MLMetadata(BaseModel):
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    prediction: Optional[str] = None
    probability: Optional[float] = None
    target_probability: Optional[float] = None
    features_used: Optional[int] = None
    details: Optional[Dict[str, Any]] = None


class ScanResultResponse(BaseModel):
    # Common identification
    id: str
    scan_id: Optional[str] = None
    scan_type: str = "url"
    input_type: Optional[str] = None
    status: str = "completed"

    # Target
    target: str

    # Timestamps
    timestamp: datetime
    created_at: Optional[datetime] = None

    # Scores and tiers
    composite_risk_score: int = Field(..., ge=0, le=100)
    risk_score: Optional[int] = None
    risk_level: str
    category: Optional[List[str]] = None
    confidence: Optional[float] = None

    # Content & explainability
    summary: str
    heuristic_score: Optional[int] = None
    indicators: List[ThreatIndicator]
    recommendation: Optional[str] = None
    recommendations: List[str] = Field(default_factory=list)
    reasons: Optional[List[str]] = None

    # Metadata & signals
    model_version: str = "rules-v1"
    normalized_url: Optional[str] = None
    features: Optional[Dict[str, Any]] = None
    ml_metadata: Optional[MLMetadata] = None
    technical_details: Optional[Dict[str, Any]] = None

    @model_validator(mode="before")
    @classmethod
    def sync_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Sync id and scan_id
            if "id" in data and "scan_id" not in data:
                data["scan_id"] = data["id"]
            elif "scan_id" in data and "id" not in data:
                data["id"] = data["scan_id"]

            # Sync scan_type and input_type
            if "scan_type" in data and "input_type" not in data:
                data["input_type"] = data["scan_type"]
            elif "input_type" in data and "scan_type" not in data:
                data["scan_type"] = data["input_type"]

            # Sync composite_risk_score and risk_score
            if "composite_risk_score" in data and "risk_score" not in data:
                data["risk_score"] = data["composite_risk_score"]
            elif "risk_score" in data and "composite_risk_score" not in data:
                data["composite_risk_score"] = data["risk_score"]

            # Sync timestamp and created_at
            if "timestamp" in data and "created_at" not in data:
                data["created_at"] = data["timestamp"]
            elif "created_at" in data and "timestamp" not in data:
                data["timestamp"] = data["created_at"]

            # Sync recommendation and recommendations
            if "recommendations" in data and ("recommendation" not in data or not data["recommendation"]):
                recs = data["recommendations"]
                data["recommendation"] = recs[0] if recs else "Exercise caution."
            elif "recommendation" in data and ("recommendations" not in data or not data["recommendations"]):
                data["recommendations"] = [data["recommendation"]]

        return data


class ScanHistoryItem(BaseModel):
    id: str
    scan_id: Optional[str] = None
    scan_type: str
    target: str
    timestamp: datetime
    composite_risk_score: int
    risk_level: str
    summary: str

    @model_validator(mode="before")
    @classmethod
    def sync_history_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "id" in data and "scan_id" not in data:
                data["scan_id"] = data["id"]
        return data
