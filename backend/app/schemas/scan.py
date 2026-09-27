from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, model_validator


# --- Request Schemas ---

class UrlScanRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048, description="URL to analyze")
    deep_analysis: Optional[bool] = Field(True, description="Enable live safe web fetch, redirect chain, and download inspection")


class MessageScanRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=5000, description="SMS or message text to analyze")
    sender: Optional[str] = Field(None, max_length=128, description="Optional sender info or phone number")

    @model_validator(mode="before")
    @classmethod
    def validate_content(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "message" not in data and "text" in data:
                data["message"] = data["text"]
            if "message" in data and isinstance(data["message"], str):
                if not data["message"].strip():
                    raise ValueError("Message content cannot be empty or pure whitespace.")
        return data


class TextScanRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000, description="SMS or message text to analyze")
    sender: Optional[str] = Field(None, max_length=128, description="Optional sender info or phone number")


class EmailScanRequest(BaseModel):
    raw_email: Optional[str] = Field(None, max_length=200000, description="Raw RFC-822 / MIME email text")
    subject: Optional[str] = Field("", max_length=512, description="Email subject line")
    sender: Optional[str] = Field(None, max_length=256, description="From email address / display name")
    body: Optional[str] = Field(None, max_length=100000, description="Email body content")
    reply_to: Optional[str] = Field(None, max_length=256, description="Reply-To header")
    attachments: Optional[List[str]] = Field(default_factory=list, description="List of attachment filenames")

    @model_validator(mode="before")
    @classmethod
    def validate_email_input(cls, data: Any) -> Any:
        if isinstance(data, dict):
            raw = data.get("raw_email")
            body = data.get("body")
            sender = data.get("sender")

            if raw is not None:
                if not isinstance(raw, str) or not raw.strip():
                    raise ValueError("Raw email content cannot be empty or pure whitespace.")
            elif body is not None or sender is not None:
                if not sender or not isinstance(sender, str) or not sender.strip():
                    raise ValueError("Sender email address is required when providing structured email fields.")
                if not body or not isinstance(body, str) or not body.strip():
                    raise ValueError("Email body content is required when providing structured email fields.")
            else:
                raise ValueError("Must provide either 'raw_email' or structured 'sender' and 'body' fields.")
        return data


class PhoneScanRequest(BaseModel):
    phone_number: str = Field(..., min_length=3, max_length=32, description="Phone number to check")
    country: Optional[str] = Field("IN", max_length=8, description="Default country or region code (e.g. IN, US, GB)")
    context: Optional[str] = Field(None, max_length=512, description="Optional caller context or claimed organization")


class ApkScanRequest(BaseModel):
    package_name: str = Field(..., min_length=3, max_length=256, description="App package name e.g. com.example.app")
    app_name: Optional[str] = Field(None, max_length=128, description="Human readable application name")
    category: Optional[str] = Field(None, max_length=64, description="Declared or apparent app category e.g. calculator, camera, messaging, utility")
    permissions: List[str] = Field(..., min_length=1, description="List of Android permissions requested by APK")


# --- Response Schemas ---

class ThreatIndicator(BaseModel):
    name: str
    severity: str = Field(..., description="critical, high, medium, low, or info")
    description: str
    evidence: Optional[str] = None
    rule_id: Optional[str] = None


class RuleDetectionDetails(BaseModel):
    risk_score: int = Field(..., ge=0, le=100)
    indicators: List[ThreatIndicator] = Field(default_factory=list)


class MLDetectionDetails(BaseModel):
    prediction: str
    model_score: float
    model_version: str
    model_probability: Optional[float] = None
    features_used: Optional[int] = None
    top_contributing_features: Optional[List[Dict[str, Any]]] = None


class DetectionSources(BaseModel):
    rules: RuleDetectionDetails
    ml: Optional[MLDetectionDetails] = None
    embedded_urls: Optional[List[Dict[str, Any]]] = None
    headers: Optional[Dict[str, Any]] = None
    attachments: Optional[List[Dict[str, Any]]] = None
    intelligence: Optional[Dict[str, Any]] = None
    permissions: Optional[Dict[str, Any]] = None
    certificate: Optional[Dict[str, Any]] = None
    components: Optional[Dict[str, Any]] = None
    privacy: Optional[Dict[str, Any]] = None
    web: Optional[Dict[str, Any]] = None
    social_engineering: Optional[Dict[str, Any]] = None


class MLMetadata(BaseModel):
    learning_type: Optional[str] = None
    category: Optional[str] = None
    algorithm: Optional[str] = None
    features_used: Optional[Union[List[str], int, Any]] = None
    confidence: Optional[float] = None
    is_deterministic: Optional[bool] = None

    # Backwards compatibility and additional model provenance
    model_name: Optional[str] = None
    model_version: Optional[str] = None
    prediction: Optional[str] = None
    probability: Optional[float] = None
    target_probability: Optional[float] = None
    details: Optional[Dict[str, Any]] = None


class ScanResultResponse(BaseModel):
    id: str
    scan_id: Optional[str] = None
    user_id: Optional[str] = None
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
    detection: Optional[DetectionSources] = None
    ml_metadata: Optional[MLMetadata] = None
    technical_details: Optional[Dict[str, Any]] = None
    privacy_analysis: Optional[Dict[str, Any]] = None
    web_analysis: Optional[Dict[str, Any]] = None
    social_engineering: Optional[Dict[str, Any]] = None
    threat_intelligence: Optional[Dict[str, Any]] = None
    threat_graph: Optional[Dict[str, Any]] = None

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
    user_id: Optional[str] = None
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
