"""
ScamBuster — Static Phone Number Features & Pattern Analysis (Phase 06)

Extracts telecom metadata, structural properties, and mathematical digit pattern features
from normalized phone numbers.

IMPORTANT DESIGN PRINCIPLES:
- Country codes, VoIP, or mobile numbers are CONTEXTUAL SIGNALS ONLY and NEVER treated as malicious by themselves.
- Pattern features (entropy, sequential digits, repeated digits) are weak signals and must not dominate risk scoring.
- Zero PII leaks: all operations run on structural properties or digit distributions.
"""

from collections import Counter
import math
import re
from typing import Any, Dict, List, Optional, Union

from app.services.phone_normalizer import NormalizedPhone, normalize_phone_number


PHONE_FEATURE_NAMES = [
    "country_code",
    "number_length",
    "national_number_length",
    "is_valid_number",
    "is_possible_number",
    "is_mobile",
    "is_fixed_line",
    "is_voip",
    "is_premium_rate",
    "is_toll_free",
    "digit_entropy",
    "unique_digit_count",
    "unique_digit_ratio",
    "max_consecutive_repeated_digits",
    "repeated_digit_ratio",
    "sequential_digit_score",
    "leading_zero_count",
    "country_match",
]


def calculate_digit_entropy(digits_str: str) -> float:
    """Calculate Shannon entropy of the digit distribution in a phone number."""
    if not digits_str:
        return 0.0
    counts = Counter(digits_str)
    length = len(digits_str)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 4)


def calculate_sequential_pattern_score(digits_str: str) -> int:
    """
    Find length of the longest consecutive ascending or descending digit sequence.
    E.g., '9876543210' -> 10, '1234' -> 4, '9876' -> 4.
    """
    if len(digits_str) <= 1:
        return len(digits_str)

    max_run = 1
    curr_inc_run = 1
    curr_dec_run = 1

    for i in range(1, len(digits_str)):
        if digits_str[i].isdigit() and digits_str[i - 1].isdigit():
            diff = int(digits_str[i]) - int(digits_str[i - 1])
            if diff == 1:
                curr_inc_run += 1
            else:
                curr_inc_run = 1

            if diff == -1:
                curr_dec_run += 1
            else:
                curr_dec_run = 1

            max_run = max(max_run, curr_inc_run, curr_dec_run)
        else:
            curr_inc_run = 1
            curr_dec_run = 1

    return max_run


def calculate_consecutive_repeated_digits(digits_str: str) -> int:
    """Find length of the longest consecutive run of identical digits (e.g. '99999' -> 5)."""
    if not digits_str:
        return 0
    max_run = 1
    curr_run = 1
    for i in range(1, len(digits_str)):
        if digits_str[i] == digits_str[i - 1]:
            curr_run += 1
            max_run = max(max_run, curr_run)
        else:
            curr_run = 1
    return max_run


def extract_phone_features(
    phone_or_normalized: Union[str, NormalizedPhone],
    default_region: Optional[str] = "IN",
) -> Dict[str, Any]:
    """
    Extract a dictionary of static and digit pattern features from a phone number.
    Returns a dictionary keyed by PHONE_FEATURE_NAMES.
    """
    if isinstance(phone_or_normalized, NormalizedPhone):
        norm = phone_or_normalized
    else:
        norm = normalize_phone_number(phone_or_normalized, default_region=default_region)

    national = re.sub(r"\D", "", norm.national_number)
    national_len = len(national)

    # Entropy & Digit distributions
    entropy = calculate_digit_entropy(national)
    unique_digits = len(set(national)) if national else 0
    unique_ratio = round(unique_digits / national_len, 4) if national_len > 0 else 0.0

    counts = Counter(national)
    most_common_count = counts.most_common(1)[0][1] if counts else 0
    repeated_ratio = round(most_common_count / national_len, 4) if national_len > 0 else 0.0

    max_consecutive_rep = calculate_consecutive_repeated_digits(national)
    seq_score = calculate_sequential_pattern_score(national)

    # Leading zeroes
    leading_zeroes = 0
    for ch in national:
        if ch == '0':
            leading_zeroes += 1
        else:
            break

    # Number type flags
    type_name = norm.number_type_name
    is_mobile = 1 if type_name in ("MOBILE", "FIXED_LINE_OR_MOBILE") else 0
    is_fixed = 1 if type_name == "FIXED_LINE" else 0
    is_voip = 1 if type_name == "VOIP" else 0
    is_premium = 1 if type_name == "PREMIUM_RATE" else 0
    is_toll_free = 1 if type_name == "TOLL_FREE" else 0

    # Total digits in E.164 (without leading +)
    total_digits_len = len(re.sub(r"\D", "", norm.e164))

    # Region match
    req_reg = (default_region or "").upper().strip()
    country_match = 1 if req_reg and req_reg == norm.region_code else (1 if not req_reg else 0)

    return {
        "country_code": int(norm.country_code or 0),
        "number_length": total_digits_len,
        "national_number_length": national_len,
        "is_valid_number": 1 if norm.is_valid else 0,
        "is_possible_number": 1 if norm.is_possible else 0,
        "is_mobile": is_mobile,
        "is_fixed_line": is_fixed,
        "is_voip": is_voip,
        "is_premium_rate": is_premium,
        "is_toll_free": is_toll_free,
        "digit_entropy": entropy,
        "unique_digit_count": unique_digits,
        "unique_digit_ratio": unique_ratio,
        "max_consecutive_repeated_digits": max_consecutive_rep,
        "repeated_digit_ratio": repeated_ratio,
        "sequential_digit_score": seq_score,
        "leading_zero_count": leading_zeroes,
        "country_match": country_match,
    }


def extract_phone_feature_vector(
    phone_or_normalized: Union[str, NormalizedPhone],
    default_region: Optional[str] = "IN",
) -> List[float]:
    """
    Extract a deterministic ordered list of float features suitable for ML classifiers.
    Order corresponds exactly to PHONE_FEATURE_NAMES.
    """
    feat_dict = extract_phone_features(phone_or_normalized, default_region=default_region)
    return [float(feat_dict[k]) for k in PHONE_FEATURE_NAMES]
