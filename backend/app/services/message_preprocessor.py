"""
ScamBuster Message Preprocessor Service (Phase 04)

Provides deterministic text normalization and entity extraction (URLs, phone numbers, emails)
while strictly preserving the original raw message separately for stylistic and security analysis.

Security & Privacy:
- Zero outbound network requests during extraction (strictly regex/lexical).
- Does not log raw message contents.
- Handles unicode spoofing and obfuscated characters via NFKC normalization.
"""

import re
import string
import unicodedata
from typing import List, NamedTuple, Optional
from pydantic import BaseModel, Field


# URL extraction regex matching http, https, and www schemes
URL_REGEX = re.compile(
    r"(?i)\b(?:https?://|www\.)[^\s<>{}\"\'\[\]`]+",
    re.IGNORECASE
)

# Email address extraction regex
EMAIL_REGEX = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

# Phone number regex: international (+...) or standard formatted (7-15 digits with optional separators)
PHONE_REGEX = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b"
)


class PreprocessedMessage(BaseModel):
    """Structured container holding normalized text alongside extracted entities and raw text."""
    original_text: str
    cleaned_text: str  # Lowercased, stripped of entities and excessive punctuation for TF-IDF
    normalized_text: str  # NFKC normalized, whitespace collapsed, case preserved
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_phone_numbers: List[str] = Field(default_factory=list)
    extracted_emails: List[str] = Field(default_factory=list)
    char_count: int
    word_count: int


def preprocess_message(text: str) -> PreprocessedMessage:
    """
    Execute full text preprocessing pipeline:
    1. Unicode NFKC normalization
    2. Entity extraction (URLs, Phone numbers, Emails)
    3. Normalization with case preservation for stylistic features
    4. Cleaned token sequence generation for TF-IDF modeling
    """
    if not isinstance(text, str):
        text = str(text or "")

    original_text = text.strip()

    # 1. Unicode NFKC normalization (collapses homoglyphs, full-width chars, ligatures)
    nfkc_text = unicodedata.normalize("NFKC", original_text)

    # Collapse internal whitespace
    normalized_text = re.sub(r"\s+", " ", nfkc_text).strip()

    # 2. Entity extraction on normalized text
    raw_urls = URL_REGEX.findall(normalized_text)
    # Deduplicate while preserving order
    urls = list(dict.fromkeys(raw_urls))

    emails = list(dict.fromkeys(EMAIL_REGEX.findall(normalized_text)))

    # For phone numbers, filter out trivial numbers (like years '2024' or small prices)
    candidate_phones = PHONE_REGEX.findall(normalized_text)
    filtered_phones = []
    for p in candidate_phones:
        digits_only = re.sub(r"\D", "", p)
        # Valid phone numbers typically have 7 to 15 digits
        if 7 <= len(digits_only) <= 15:
            filtered_phones.append(p.strip())
    phone_numbers = list(dict.fromkeys(filtered_phones))

    # 3. Cleaned text for TF-IDF classifier
    # Lowercase
    cleaned = normalized_text.lower()
    # Strip URLs
    cleaned = URL_REGEX.sub(" ", cleaned)
    # Strip Emails
    cleaned = EMAIL_REGEX.sub(" ", cleaned)
    # Strip Phone Numbers
    cleaned = PHONE_REGEX.sub(" ", cleaned)
    # Strip punctuation
    cleaned = cleaned.translate(str.maketrans("", "", string.punctuation))
    # Collapse whitespace
    cleaned = re.sub(r"\s+", " ", cleaned).strip()

    words = normalized_text.split()

    return PreprocessedMessage(
        original_text=original_text,
        cleaned_text=cleaned,
        normalized_text=normalized_text,
        extracted_urls=urls,
        extracted_phone_numbers=phone_numbers,
        extracted_emails=emails,
        char_count=len(original_text),
        word_count=len(words),
    )
