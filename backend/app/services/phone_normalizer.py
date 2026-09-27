"""
ScamBuster — Phone Normalizer & Privacy Protection Service (Phase 06)

Uses Google libphonenumber (python-phonenumbers) to validate, normalize,
and extract international telecom metadata while strictly enforcing user privacy.

Privacy Principles:
- Raw phone numbers are sensitive PII and must never be leaked to general application logs.
- Generates privacy-preserving masked representations for UI/logging (e.g. +91 ******3210).
- Generates keyed HMAC-SHA256 tokens for lookup/storage to avoid brute-force enumeration.
"""

from dataclasses import dataclass
import hashlib
import hmac
import os
import re
from typing import Optional, Tuple
import phonenumbers
from phonenumbers import PhoneNumberType


# Keyed HMAC secret for phone number tokenization
HMAC_SECRET = os.getenv("SCAMBUSTER_PHONE_HMAC_SECRET", "scambuster-telecom-privacy-default-salt-2026").encode("utf-8")


@dataclass
class NormalizedPhone:
    raw_input: str
    is_valid: bool
    is_possible: bool
    e164: str                  # Canonical E.164: e.g. "+919876543210"
    masked: str                # Masked PII: e.g. "+91 ******3210"
    hmac_token: str            # Keyed HMAC for storage
    country_code: int          # e.g. 91
    region_code: str           # e.g. "IN", "US", "GB"
    national_number: str       # e.g. "9876543210"
    number_type_name: str      # "MOBILE", "FIXED_LINE", "VOIP", "PREMIUM_RATE", "TOLL_FREE", "UNKNOWN"
    carrier_name: Optional[str] = None


def mask_phone_number(e164: str, country_code: Optional[int] = None) -> str:
    """
    Produce a privacy-preserving masked display string for a phone number.
    Retains country code prefix and last 4 digits; masks all intermediate digits.
    Example: '+919876543210' -> '+91 ******3210'
    """
    if not e164:
        return "Unknown"

    cc_prefix = None
    national = None

    if country_code and country_code > 0:
        candidate_cc = f"+{country_code}"
        if e164.startswith(candidate_cc):
            cc_prefix = candidate_cc
            national = e164[len(candidate_cc):]

    if not cc_prefix or not national:
        try:
            p = phonenumbers.parse(e164, None)
            cc_prefix = f"+{p.country_code}"
            national = str(p.national_number)
        except Exception:
            pass

    if not cc_prefix or not national:
        m = re.match(r"^(\+\d{1,3})(\d+)$", e164)
        if m:
            cc_prefix, national = m.group(1), m.group(2)
        else:
            if len(e164) <= 4:
                return "****"
            return e164[:2] + "****" + e164[-2:]

    if len(national) <= 4:
        return f"{cc_prefix} ****"

    masked_middle = "*" * max(len(national) - 4, 4)
    last_four = national[-4:]
    return f"{cc_prefix} {masked_middle}{last_four}"


def generate_phone_hmac(e164: str) -> str:
    """
    Generate a keyed HMAC-SHA256 representation of the canonical E.164 phone number.
    Protects against brute-force enumeration of the finite phone-number space.
    """
    return hmac.new(HMAC_SECRET, e164.encode("utf-8"), hashlib.sha256).hexdigest()


def normalize_phone_number(
    phone_input: str,
    default_region: Optional[str] = None
) -> NormalizedPhone:
    """
    Parse, validate, and normalize a user-provided phone number into canonical E.164.
    Supports international prefixes (+...) and local numbers when default_region is supplied.
    """
    clean_input = re.sub(r"[^\d+]", "", str(phone_input or "").strip())
    if not clean_input:
        return NormalizedPhone(
            raw_input=str(phone_input or ""),
            is_valid=False,
            is_possible=False,
            e164="",
            masked="Empty",
            hmac_token="",
            country_code=0,
            region_code="UNKNOWN",
            national_number="",
            number_type_name="UNKNOWN",
        )

    # Sanitize region code
    region = (default_region or "IN").upper().strip() if default_region else None

    try:
        parsed = phonenumbers.parse(clean_input, region)
        is_possible = phonenumbers.is_possible_number(parsed)
        is_valid = phonenumbers.is_valid_number(parsed)

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164) if is_possible else clean_input
        country_code = parsed.country_code
        national_str = str(parsed.national_number)
        region_code = phonenumbers.region_code_for_number(parsed) or "ZZ"

        num_type_enum = phonenumbers.number_type(parsed)
        type_names = {
            PhoneNumberType.FIXED_LINE: "FIXED_LINE",
            PhoneNumberType.MOBILE: "MOBILE",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "FIXED_LINE_OR_MOBILE",
            PhoneNumberType.TOLL_FREE: "TOLL_FREE",
            PhoneNumberType.PREMIUM_RATE: "PREMIUM_RATE",
            PhoneNumberType.SHARED_COST: "SHARED_COST",
            PhoneNumberType.VOIP: "VOIP",
            PhoneNumberType.PERSONAL_NUMBER: "PERSONAL_NUMBER",
            PhoneNumberType.PAGER: "PAGER",
            PhoneNumberType.UAN: "UAN",
            PhoneNumberType.VOICEMAIL: "VOICEMAIL",
            PhoneNumberType.UNKNOWN: "UNKNOWN",
        }
        type_name = type_names.get(num_type_enum, "UNKNOWN")

    except Exception:
        # Fallback if parsing library fails on non-standard string
        is_possible = False
        is_valid = False
        e164 = clean_input if clean_input.startswith("+") else f"+{clean_input}"
        country_code = 0
        national_str = re.sub(r"^\+", "", clean_input)
        region_code = "UNKNOWN"
        type_name = "UNKNOWN"

    masked = mask_phone_number(e164, country_code=country_code)
    hmac_tok = generate_phone_hmac(e164)

    return NormalizedPhone(
        raw_input=phone_input,
        is_valid=is_valid,
        is_possible=is_possible,
        e164=e164,
        masked=masked,
        hmac_token=hmac_tok,
        country_code=country_code,
        region_code=region_code,
        national_number=national_str,
        number_type_name=type_name,
    )
