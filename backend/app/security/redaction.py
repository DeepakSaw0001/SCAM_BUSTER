"""
ScamBuster — Privacy & PII Redaction Engine (Phase 10)

Provides deterministic detection and masking of sensitive PII, credentials,
and payment data for:
1. Operational application logging (strictly zero raw secrets logged)
2. Safe technical detail summaries
3. Defense against accidental log leakage of credentials or private user identifiers.

Redaction targets:
- Email addresses
- Phone numbers
- OTP / verification codes (4 to 8 digit tokens in verification contexts)
- Credit card numbers (13 to 19 digits passing or resembling Luhn format)
- CVV codes (3 to 4 digits in card context)
- API keys, JWT tokens, Bearer authorization tokens
- Passwords and secret values
"""

import re
from typing import Any, Dict, List, Optional, Union


# Regex patterns for PII detection
EMAIL_PATTERN = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# Phone number pattern (international or local 7-15 digits)
PHONE_PATTERN = re.compile(
    r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b"
)

# Credit card pattern (13 to 19 digits, possibly hyphen or space separated)
CREDIT_CARD_PATTERN = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{1,7}\b|\b\d{13,19}\b"
)

# OTP / Verification code pattern (4 to 8 digits in proximity to OTP context words)
OTP_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(?:otp|code|pin|token|verification|password)\s*[:=is\-\s]*([0-9]{4,8})\b"
)

# CVV pattern in card context
CVV_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(?:cvv|cvc|security code|cid)\s*[:=is\-\s]*([0-9]{3,4})\b"
)

# API Keys & Tokens (Bearer tokens, generic hex/base64 keys >= 24 chars)
TOKEN_PATTERN = re.compile(
    r"(?i)\b(?:bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*|"
    r"(?:api[_-]?key|secret|token|auth)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,64})['\"]?)\b"
)


def is_luhn_valid(number_str: str) -> bool:
    """Validate digits against Luhn algorithm (ISO/IEC 7812)."""
    digits = [int(d) for d in re.sub(r"\D", "", number_str)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return (checksum % 10) == 0


def mask_email(email_str: str) -> str:
    """Mask email preserving first char and domain: u***@domain.com."""
    parts = email_str.split("@")
    if len(parts) != 2:
        return "[REDACTED_EMAIL]"
    local, domain = parts
    if len(local) <= 2:
        masked_local = local[0] + "***" if local else "***"
    else:
        masked_local = local[0] + "***" + local[-1]
    return f"{masked_local}@{domain}"


def mask_phone(phone_str: str) -> str:
    """Mask phone preserving country/area code and last 2 digits."""
    digits = re.sub(r"\D", "", phone_str)
    if len(digits) < 7:
        return "[REDACTED_PHONE]"
    return f"+{digits[:2]}***{digits[-2:]}" if phone_str.startswith("+") else f"***{digits[-4:]}"


def mask_credit_card(card_str: str) -> str:
    """Mask card preserving first 4 and last 4 digits: 4111-****-****-1111."""
    digits = re.sub(r"\D", "", card_str)
    if len(digits) < 8:
        return "[REDACTED_CARD]"
    return f"{digits[:4]}-****-****-{digits[-4:]}"


def redact_sensitive_text(text: str, mask_emails: bool = True, mask_phones: bool = True) -> str:
    """
    Scrub raw text of credentials, OTPs, card numbers, tokens, and PII.
    Safe for operational application logs and metrics.
    """
    if not text:
        return ""

    redacted = text

    # 1. Redact Tokens & API Keys
    redacted = TOKEN_PATTERN.sub("[REDACTED_AUTH_TOKEN]", redacted)

    # 2. Redact OTPs in context
    def _mask_otp(match: re.Match) -> str:
        full = match.group(0)
        code = match.group(1)
        return full.replace(code, "[REDACTED_OTP]")

    redacted = OTP_CONTEXT_PATTERN.sub(_mask_otp, redacted)

    # 3. Redact CVVs in context
    def _mask_cvv(match: re.Match) -> str:
        full = match.group(0)
        code = match.group(1)
        return full.replace(code, "[REDACTED_CVV]")

    redacted = CVV_CONTEXT_PATTERN.sub(_mask_cvv, redacted)

    # 4. Redact Credit Card Numbers
    for match in CREDIT_CARD_PATTERN.finditer(redacted):
        candidate = match.group(0)
        digits = re.sub(r"\D", "", candidate)
        if 13 <= len(digits) <= 19:
            # Check Luhn or 16-digit blocks
            if len(digits) == 16 or is_luhn_valid(digits):
                redacted = redacted.replace(candidate, mask_credit_card(candidate))

    # 5. Redact Emails (if requested)
    if mask_emails:
        for match in EMAIL_PATTERN.finditer(redacted):
            em = match.group(0)
            redacted = redacted.replace(em, mask_email(em))

    # 6. Redact Phones (if requested)
    if mask_phones:
        for match in PHONE_PATTERN.finditer(redacted):
            ph = match.group(0)
            digits = re.sub(r"\D", "", ph)
            if 7 <= len(digits) <= 15:
                # Avoid redacting 4-digit years like 2024 or small monetary amounts
                if not (len(digits) == 4 and (digits.startswith("19") or digits.startswith("20"))):
                    redacted = redacted.replace(ph, mask_phone(ph))

    return redacted


def sanitize_log_dict(data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
    """
    Recursively sanitize dictionaries before logging to prevent accidental PII leakage.
    Limits recursion depth to 5.
    """
    if depth > 5:
        return "[TRUNCATED_NESTING]"

    sanitized: Dict[str, Any] = {}
    sensitive_keys = {
        "password", "otp", "pin", "cvv", "token", "secret", "card_number",
        "authorization", "api_key", "private_key", "cookie", "ssn"
    }

    for key, val in data.items():
        k_lower = str(key).lower()
        if any(s in k_lower for s in sensitive_keys):
            sanitized[key] = "[REDACTED_SECRET]"
        elif isinstance(val, str):
            sanitized[key] = redact_sensitive_text(val, mask_emails=False, mask_phones=False)
        elif isinstance(val, dict):
            sanitized[key] = sanitize_log_dict(val, depth=depth + 1)
        elif isinstance(val, list):
            sanitized[key] = [
                sanitize_log_dict(item, depth=depth + 1) if isinstance(item, dict)
                else (redact_sensitive_text(item) if isinstance(item, str) else item)
                for item in val[:20]  # Cap list to 20 to prevent gigantic dumps
            ]
        else:
            sanitized[key] = val

    return sanitized
