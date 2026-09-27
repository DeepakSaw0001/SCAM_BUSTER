"""
ScamBuster Message Feature Extractor (Phase 04)

Extracts structured statistical, lexical, and social-engineering features from
SMS / text messages. These features provide explainability for human review and
complement the statistical TF-IDF NLP model.

IMPORTANT:
These indicators represent statistical and heuristic patterns, NOT definitive proof of fraud.
"""

import re
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field

from app.services.message_preprocessor import (
    PreprocessedMessage,
    preprocess_message,
)

# ── Feature Names ────────────────────────────────────────────────────────
MESSAGE_STATISTICAL_FEATURES = [
    "message_length",
    "word_count",
    "character_count",
    "sentence_count",
    "average_word_length",
    "uppercase_ratio",
    "digit_ratio",
    "special_character_ratio",
    "exclamation_count",
    "question_mark_count",
]

MESSAGE_STRUCTURAL_FEATURES = [
    "url_count",
    "phone_number_count",
    "email_count",
    "has_url",
    "has_phone_number",
    "has_email",
]

MESSAGE_SEMANTIC_FEATURES = [
    "urgency_terms_count",
    "credential_terms_count",
    "financial_terms_count",
    "threat_terms_count",
    "reward_terms_count",
    "authority_terms_count",
    "call_to_action_count",
]

ALL_MESSAGE_FEATURES = (
    MESSAGE_STATISTICAL_FEATURES
    + MESSAGE_STRUCTURAL_FEATURES
    + MESSAGE_SEMANTIC_FEATURES
)

# ── Social Engineering Dictionaries ──────────────────────────────────────
URGENCY_KEYWORDS = {
    "urgent", "immediately", "immediate", "act now", "expires", "hurry",
    "deadline", "limited time", "final notice", "critical", "at once",
    "within 24 hours", "within 12 hours", "today only", "quick", "asap"
}

CREDENTIAL_KEYWORDS = {
    "password", "pin", "otp", "token", "passcode", "security code",
    "verification code", "verify your account", "verify account",
    "login", "log in", "credentials", "identity", "social security",
    "ssn", "seed phrase", "private key"
}

FINANCIAL_KEYWORDS = {
    "bank", "cash", "money", "dollars", "payment", "transfer", "refund",
    "deposit", "overdue", "invoice", "wire", "crypto", "bitcoin", "btc",
    "account balance", "debit", "credit card", "payroll", "funds"
}

THREAT_KEYWORDS = {
    "suspended", "suspend", "locked", "disabled", "terminated", "restricted",
    "fraud", "unauthorized", "legal action", "lawsuit", "arrest", "warrant",
    "police", "court", "investigation", "penalty", "frozen"
}

REWARD_KEYWORDS = {
    "winner", "won", "prize", "free", "claim", "jackpot", "lottery",
    "voucher", "gift card", "reward", "congratulations", "selected",
    "bonus", "giveaway", "survey reward"
}

AUTHORITY_KEYWORDS = {
    "irs", "usps", "fedex", "dhl", "ups", "postal", "delivery", "customs",
    "chase", "bank of america", "wells fargo", "paypal", "amazon", "apple",
    "microsoft", "netflix", "walmart", "target", "internal revenue"
}

CTA_KEYWORDS = {
    "click", "visit", "link", "reply", "text", "call", "dial", "download",
    "open", "follow", "fill", "submit", "confirm", "update"
}


def _count_keyword_matches(text_lower: str, keywords: set) -> int:
    """Count occurrences of keywords from a dictionary in lowercased text."""
    count = 0
    for kw in keywords:
        # Match whole phrase or word boundary
        pattern = r"\b" + re.escape(kw) + r"\b"
        matches = re.findall(pattern, text_lower)
        count += len(matches)
    return count


class MessageFeatures(BaseModel):
    """Structured Pydantic model for SMS features."""
    message_length: int
    word_count: int
    character_count: int
    sentence_count: int
    average_word_length: float
    uppercase_ratio: float
    digit_ratio: float
    special_character_ratio: float
    exclamation_count: int
    question_mark_count: int
    url_count: int
    phone_number_count: int
    email_count: int
    has_url: bool
    has_phone_number: bool
    has_email: bool
    urgency_terms_count: int
    credential_terms_count: int
    financial_terms_count: int
    threat_terms_count: int
    reward_terms_count: int
    authority_terms_count: int
    call_to_action_count: int


def extract_message_features(
    text: str,
    preprocessed: Optional[PreprocessedMessage] = None
) -> MessageFeatures:
    """
    Extract full suite of statistical, structural, and social-engineering features
    from raw message string or preprocessed message container.
    """
    if preprocessed is None:
        preprocessed = preprocess_message(text)

    raw = preprocessed.original_text
    norm = preprocessed.normalized_text
    lower = norm.lower()
    words = norm.split()
    total_chars = len(raw)

    # Statistical metrics
    word_count = len(words)
    total_letters = sum(1 for c in raw if c.isalpha())
    uppercase_count = sum(1 for c in raw if c.isupper())
    uppercase_ratio = round(uppercase_count / total_letters, 4) if total_letters > 0 else 0.0

    digit_count = sum(1 for c in raw if c.isdigit())
    digit_ratio = round(digit_count / total_chars, 4) if total_chars > 0 else 0.0

    special_chars = sum(1 for c in raw if not c.isalnum() and not c.isspace())
    special_ratio = round(special_chars / total_chars, 4) if total_chars > 0 else 0.0

    avg_word_len = (
        round(sum(len(w) for w in words) / word_count, 2)
        if word_count > 0
        else 0.0
    )

    # Split into sentences via common ending punctuation
    sentences = [s for s in re.split(r"[.!?]+", raw) if s.strip()]
    sentence_count = max(len(sentences), 1 if total_chars > 0 else 0)

    exclamation_count = raw.count("!")
    question_mark_count = raw.count("?")

    # Structural metrics
    url_count = len(preprocessed.extracted_urls)
    phone_count = len(preprocessed.extracted_phone_numbers)
    email_count = len(preprocessed.extracted_emails)

    # Social engineering keyword metrics
    urgency_count = _count_keyword_matches(lower, URGENCY_KEYWORDS)
    credential_count = _count_keyword_matches(lower, CREDENTIAL_KEYWORDS)
    financial_count = _count_keyword_matches(lower, FINANCIAL_KEYWORDS)
    threat_count = _count_keyword_matches(lower, THREAT_KEYWORDS)
    reward_count = _count_keyword_matches(lower, REWARD_KEYWORDS)
    authority_count = _count_keyword_matches(lower, AUTHORITY_KEYWORDS)
    cta_count = _count_keyword_matches(lower, CTA_KEYWORDS)

    return MessageFeatures(
        message_length=total_chars,
        word_count=word_count,
        character_count=len(raw.replace(" ", "")),
        sentence_count=sentence_count,
        average_word_length=avg_word_len,
        uppercase_ratio=uppercase_ratio,
        digit_ratio=digit_ratio,
        special_character_ratio=special_ratio,
        exclamation_count=exclamation_count,
        question_mark_count=question_mark_count,
        url_count=url_count,
        phone_number_count=phone_count,
        email_count=email_count,
        has_url=url_count > 0,
        has_phone_number=phone_count > 0,
        has_email=email_count > 0,
        urgency_terms_count=urgency_count,
        credential_terms_count=credential_count,
        financial_terms_count=financial_count,
        threat_terms_count=threat_count,
        reward_terms_count=reward_count,
        authority_terms_count=authority_count,
        call_to_action_count=cta_count,
    )
