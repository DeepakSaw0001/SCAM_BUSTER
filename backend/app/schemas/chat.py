"""
ScamBuster AI Security Assistant — Chat Schemas
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    role: str = Field(..., description="Message role: 'user', 'assistant', or 'system'")
    content: str = Field(..., min_length=1, description="Text content of the message")
    timestamp: Optional[str] = Field(None, description="ISO timestamp of message")


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=10000, description="User prompt or suspicious text")
    history: List[ChatMessage] = Field(default_factory=list, description="Recent conversation turns")
    context: Optional[Dict[str, Any]] = Field(default=None, description="Optional page context or client metadata")


class ChatExtractedIndicator(BaseModel):
    type: str = Field(..., description="Indicator type: url, phone, email, hash, domain")
    value: str = Field(..., description="Extracted indicator value")
    risk_score: Optional[int] = Field(None, description="Heuristic or intel risk score (0-100)")
    risk_level: Optional[str] = Field(None, description="Risk level string: SAFE, LOW, MEDIUM, HIGH, CRITICAL")


class ChatTriageResult(BaseModel):
    has_threat_detected: bool = Field(False, description="Whether immediate scam/threat patterns were found")
    risk_level: Optional[str] = Field("SAFE", description="Triage risk tier")
    scam_category: Optional[str] = Field(None, description="Primary social engineering or scam category")
    confidence: Optional[float] = Field(None, description="Confidence score 0.0 - 1.0")
    emergency_actions: List[str] = Field(default_factory=list, description="Immediate protective actions")
    red_flags: List[str] = Field(default_factory=list, description="Key red flag indicators discovered")


class ChatSuggestedAction(BaseModel):
    label: str = Field(..., description="Button label")
    action_type: str = Field(..., description="Action type: 'navigate' or 'scan'")
    target: str = Field(..., description="Navigation route or scanner target value")


class ChatResponse(BaseModel):
    reply: str = Field(..., description="Assistant markdown response")
    indicators: List[ChatExtractedIndicator] = Field(default_factory=list, description="Extracted indicators")
    triage: Optional[ChatTriageResult] = Field(None, description="Security triage results")
    suggested_prompts: List[str] = Field(default_factory=list, description="Quick follow-up prompt suggestions")
    suggested_actions: List[ChatSuggestedAction] = Field(default_factory=list, description="Interactive action buttons")
