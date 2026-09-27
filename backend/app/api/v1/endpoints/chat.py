"""
ScamBuster AI Security Assistant API Endpoint
Provides conversational cybersecurity triage, threat intelligence correlation, and guidance.
"""

from fastapi import APIRouter, HTTPException
from typing import List

from app.schemas.chat import ChatRequest, ChatResponse
from app.services.ai_assistant import get_ai_assistant_service

router = APIRouter()


@router.post("", response_model=ChatResponse, summary="Send message to AI Security Assistant")
async def chat_with_assistant(request: ChatRequest) -> ChatResponse:
    """
    Process user query, extract security indicators (URLs, emails, phones),
    evaluate social engineering tactics, and provide actionable security triage.
    """
    try:
        service = get_ai_assistant_service()
        response = service.handle_chat(request)
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process chat request: {str(e)}")


@router.get("/prompts", response_model=List[str], summary="Get starter prompt suggestions")
async def get_starter_prompts() -> List[str]:
    """Return curated starter prompts for the AI Security Assistant."""
    return [
        "🚨 Someone asked for my OTP — is it a scam?",
        "🔍 Analyze this message: 'URGENT: Your Chase account is locked. Verify at http://192.168.1.1/login'",
        "📱 How can I tell if an APK download has hidden spyware?",
        "📦 I received a text about a failed package delivery with a link. What should I do?",
        "💸 I already transferred money to a caller. What are my immediate emergency steps?",
        "🛡️ What are the top red flags of phishing emails?",
    ]
